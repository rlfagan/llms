#!/usr/bin/env python3
"""
claudescan - Analyze any GitHub or GitLab repository for AI components.
Usage: python scan.py
"""

import sys
import os
import re
import subprocess
import webbrowser
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

import anthropic
from aibom import parse_versions_from_requirements, build_aibom, write_aibom, build_aibom_html_section
from topology import build_topology_prompt, extract_json_from_response, build_topology_html, write_topology

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env",
             "dist", "build", ".next", "vendor", "target"}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff",
             ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar",
             ".gz", ".pyc", ".min.js", ".min.css"}
# Scanner output files committed to repos — skip these to avoid ingesting
# stale Grype/Trivy/Snyk/OWASP results as if they were live findings.
SKIP_SCANNER_PATTERNS = re.compile(
    r'(grype|trivy|snyk|owasp|dependency.check|anchore|clair|dockle|syft'
    r'|sbom|spdx|cyclonedx|semgrep|bandit|safety.report|osv.report'
    r'|vulnerability.report|scan.report|scan.result|vuln.report)'
    r'.*\.(json|sarif|xml|html|txt|csv|spdx)$',
    re.IGNORECASE
)
AI_INDICATOR_FILES = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py",
    "setup.cfg", "Pipfile", "package.json", "go.mod", "Cargo.toml",
    "Gemfile", "composer.json", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".env.example", "Makefile",
}
AI_KEYWORDS = {
    "openai", "anthropic", "claude", "langchain", "llamaindex", "llama_index",
    "huggingface", "transformers", "torch", "tensorflow", "keras", "jax",
    "sklearn", "scikit", "spacy", "nltk", "gpt", "llm", "embedding",
    "pinecone", "weaviate", "chroma", "faiss", "qdrant", "milvus",
    "cohere", "gemini", "mistral", "ollama", "litellm", "openrouter",
    "together", "replicate", "groq", "perplexity", "vectorstore",
    "langsmith", "mlflow", "wandb",
}

MODEL_PATTERNS = [
    r'gpt-4[o\w\-\.]*',
    r'gpt-3\.5[o\w\-\.]*',
    r'claude-[\w\.\-]+',
    r'gemini-[\w\.\-]+',
    r'mistral-[\w\.\-]+',
    r'llama[\-_]?[\w\.\-]*',
    r'mixtral[\-_]?[\w\.\-]*',
    r'deepseek[\-_]?[\w\.\-]*',
    r'command[\-_]r[\w\.\-]*',
    r'titan[\-_][\w\.\-]+',
    r'nova[\-_][\w\.\-]+',
    r'sonar[\-_]?[\w\.\-]*',
    r'o1[\-\w]*',
    r'o3[\-\w]*',
    r'text[\-_]embedding[\-_][\w\.\-]+',
]

# CVE pattern
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Report sections (must match what Claude produces)
SECTIONS = [
    ("ai-frameworks",       "AI Frameworks & Libraries"),
    ("llm-integrations",    "LLM Integrations"),
    ("embeddings",          "Embeddings & Vector Search"),
    ("agents",              "AI Agents & Orchestration"),
    ("ml-models",           "ML Models"),
    ("prompt-engineering",  "Prompt Engineering"),
    ("ai-infrastructure",   "AI Infrastructure"),
    ("security-concerns",   "Security Concerns"),
    ("confirmed-models",    "Confirmed Models in Codebase"),
    ("ai-bom",              "AI Bill of Materials"),
    ("ai-topology",         "AI System Topology"),
]

MAX_FILE_SIZE = 100_000
MAX_TOTAL_CHARS = 180_000


# ---------------------------------------------------------------------------
# Model reference finder
# ---------------------------------------------------------------------------
def find_model_references(repo_dir, repo_url):
    root = Path(repo_dir)
    refs = {}

    parsed = urlparse(repo_url)
    base = repo_url.rstrip("/")
    is_github = "github.com" in parsed.netloc
    is_gitlab = "gitlab.com" in parsed.netloc

    def make_link(rel_path, line_no):
        if is_github:
            return f"{base}/blob/main/{rel_path}#L{line_no}"
        elif is_gitlab:
            return f"{base}/-/blob/main/{rel_path}#L{line_no}"
        return f"{base}/{rel_path}"

    combined = re.compile("|".join(MODEL_PATTERNS), re.IGNORECASE)

    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        if any(p in SKIP_DIRS for p in f.parts):
            continue
        if f.suffix.lower() in SKIP_EXTS:
            continue
        if SKIP_SCANNER_PATTERNS.search(f.name):
            continue
        if f.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            lines = f.read_text(errors="replace").splitlines()
            rel = str(f.relative_to(root))
            for i, line in enumerate(lines, 1):
                for m in combined.finditer(line):
                    model = m.group(0).lower().rstrip(".,;\"')")
                    if model not in refs:
                        refs[model] = []
                    refs[model].append({
                        "file": rel,
                        "line": i,
                        "snippet": line.strip()[:120],
                        "url": make_link(rel, i),
                    })
        except Exception:
            pass

    for model in refs:
        seen = set()
        deduped = []
        for r in refs[model]:
            key = (r["file"], r["line"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        refs[model] = deduped[:5]

    return refs


# ---------------------------------------------------------------------------
# CVE context classifier — no API key needed, uses file path + snippet
# ---------------------------------------------------------------------------

# File name patterns that indicate a CVE reference is a fix/changelog entry
_FIX_FILE_PATTERNS = re.compile(
    r'(changelog|changes|history|release|releases|security|advisory|advisories'
    r'|migration|upgrade|whatsnew|news|patch|patches|fixes)',
    re.IGNORECASE
)
# Dependency manifest files — CVE here means it's an active vulnerable dep
_DEP_FILES = {
    "requirements.txt", "requirements-dev.txt", "requirements-lock.txt",
    "package.json", "package-lock.json", "yarn.lock",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "gemfile", "gemfile.lock", "composer.json", "composer.lock",
    "pyproject.toml", "setup.cfg", "pipfile", "pipfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
}
# Snippet keywords that strongly indicate a fix/patch context
_FIX_KEYWORDS = re.compile(
    r'\b(fix(ed|es|ing)?|patch(ed|es|ing)?|resolv(ed|es|ing)?|mitigat(ed|es|ing)?'
    r'|address(ed|es|ing)?|upgrad(ed|es|ing)?|bump(ed|s)?|clos(ed|es|ing)?'
    r'|remediat(ed|es|ing)?)\b',
    re.IGNORECASE
)
# Test file patterns
_TEST_PATTERNS = re.compile(r'(test_|_test\b|/tests?/|/spec/|\.spec\.|\.test\.)', re.IGNORECASE)
# Comment line prefixes
_COMMENT_START = re.compile(r'^\s*(#|//|/\*|\*|<!--|;|--)')
# Doc-only extensions
_DOC_EXTS = {".md", ".rst", ".txt", ".adoc", ".asciidoc", ".html", ".htm"}


def _classify_cve_ref(file_path, snippet):
    """
    Classify a CVE reference by file context and snippet content.
    Returns one of: "ACTIVE", "FIXED", "TEST", "DOC"
    """
    path_lower = file_path.lower()
    filename = Path(file_path).name.lower()
    ext = Path(file_path).suffix.lower()

    # Dependency manifest → treat as active inclusion
    if filename in _DEP_FILES:
        return "ACTIVE"

    # Test file → informational
    if _TEST_PATTERNS.search(path_lower):
        return "TEST"

    # Doc-only file extension → documentation reference
    if ext in _DOC_EXTS:
        # But check if the doc is a security advisory / changelog (fixed)
        if _FIX_FILE_PATTERNS.search(path_lower):
            return "FIXED"
        return "DOC"

    # Fix/changelog file name
    if _FIX_FILE_PATTERNS.search(path_lower):
        return "FIXED"

    # Comment line in source code
    if _COMMENT_START.match(snippet):
        # Comment referencing a fix keyword → FIXED
        if _FIX_KEYWORDS.search(snippet):
            return "FIXED"
        return "DOC"

    # Code line with fix keyword → fixed inline
    if _FIX_KEYWORDS.search(snippet):
        return "FIXED"

    # Default: treat as active reference
    return "ACTIVE"


# ---------------------------------------------------------------------------
# CVE finder — scan repo files for CVE IDs, classify context
# ---------------------------------------------------------------------------
def find_cves(repo_dir, repo_url):
    root = Path(repo_dir)
    cves = {}  # CVE-ID -> list of {file, line, snippet, url, context}

    parsed = urlparse(repo_url)
    base = repo_url.rstrip("/")
    is_github = "github.com" in parsed.netloc
    is_gitlab = "gitlab.com" in parsed.netloc

    def make_link(rel_path, line_no):
        if is_github:
            return f"{base}/blob/main/{rel_path}#L{line_no}"
        elif is_gitlab:
            return f"{base}/-/blob/main/{rel_path}#L{line_no}"
        return f"{base}/{rel_path}"

    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        if f.suffix.lower() in SKIP_EXTS:
            continue
        if SKIP_SCANNER_PATTERNS.search(f.name):
            continue
        if f.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            lines = f.read_text(errors="replace").splitlines()
            rel = str(f.relative_to(root))
            for i, line in enumerate(lines, 1):
                for m in CVE_PATTERN.finditer(line):
                    cve_id = m.group(0).upper()
                    if cve_id not in cves:
                        cves[cve_id] = []
                    snippet = line.strip()[:120]
                    cves[cve_id].append({
                        "file": rel,
                        "line": i,
                        "snippet": snippet,
                        "url": make_link(rel, i),
                        "context": _classify_cve_ref(rel, snippet),
                    })
        except Exception:
            pass

    # Deduplicate per CVE
    for cve in cves:
        seen = set()
        deduped = []
        for r in cves[cve]:
            key = (r["file"], r["line"])
            if key not in seen:
                seen.add(key)
                deduped.append(r)
        cves[cve] = deduped[:5]

    # Roll up: a CVE is ACTIVE if ANY reference is ACTIVE, else FIXED/TEST/DOC
    for cve_id, refs in cves.items():
        contexts = {r["context"] for r in refs}
        if "ACTIVE" in contexts:
            overall = "ACTIVE"
        elif "TEST" in contexts:
            overall = "TEST"
        elif "FIXED" in contexts:
            overall = "FIXED"
        else:
            overall = "DOC"
        for r in refs:
            r["overall_context"] = overall

    return cves


# ---------------------------------------------------------------------------
# Repo content collector
# ---------------------------------------------------------------------------
def collect_repo_content(repo_dir):
    root = Path(repo_dir)
    chunks = []
    total = 0

    def has_ai_keyword(text):
        low = text.lower()
        return any(kw in low for kw in AI_KEYWORDS)

    for f in sorted(root.rglob("*")):
        if total > MAX_TOTAL_CHARS:
            break
        if not f.is_file():
            continue
        if any(p in SKIP_DIRS for p in f.parts):
            continue
        if SKIP_SCANNER_PATTERNS.search(f.name):
            continue
        if f.name in AI_INDICATOR_FILES:
            try:
                text = f.read_text(errors="replace")
                rel = f.relative_to(root)
                chunk = f"\n\n### {rel}\n```\n{text[:8000]}\n```"
                chunks.append(chunk)
                total += len(chunk)
            except Exception:
                pass

    for f in sorted(root.rglob("*")):
        if total > MAX_TOTAL_CHARS:
            break
        if not f.is_file() or f.name in AI_INDICATOR_FILES:
            continue
        if any(p in SKIP_DIRS for p in f.parts):
            continue
        if f.suffix.lower() in SKIP_EXTS:
            continue
        if SKIP_SCANNER_PATTERNS.search(f.name):
            continue
        if f.stat().st_size > MAX_FILE_SIZE:
            continue
        try:
            text = f.read_text(errors="replace")
            if has_ai_keyword(text):
                rel = f.relative_to(root)
                chunk = f"\n\n### {rel}\n```\n{text[:6000]}\n```"
                chunks.append(chunk)
                total += len(chunk)
        except Exception:
            pass

    return "".join(chunks) if chunks else "(no relevant files found)"


# ---------------------------------------------------------------------------
# Claude analysis
# ---------------------------------------------------------------------------
def analyze_with_claude(repo_url, content):
    client = anthropic.Anthropic()

    system = """You are an expert AI/ML security and code analyst. Analyze repository files for AI components and produce a structured Markdown report.

Use EXACTLY these section headings (Claude uses them for navigation):
## 1. AI Frameworks & Libraries
## 2. LLM Integrations
## 3. Embeddings & Vector Search
## 4. AI Agents & Orchestration
## 5. ML Models
## 6. Prompt Engineering
## 7. AI Infrastructure
## 8. Security Concerns
## Summary

Skip any section with no findings but keep the heading.
Use markdown tables where appropriate.
For Security Concerns, explicitly list any CVE IDs mentioned in the codebase."""

    user = f"Analyze this repository for AI components.\nURL: {repo_url}\n\nRepository file contents:\n{content}"

    print("Sending to Claude for analysis...\n", flush=True)

    with client.messages.stream(
        model="claude-opus-4-6",
        max_tokens=8192,
        system=system,
        messages=[{"role": "user", "content": user}],
    ) as stream:
        result = []
        for text in stream.text_stream:
            print(text, end="", flush=True)
            result.append(text)
        print("\n")
        return "".join(result)


# ---------------------------------------------------------------------------
# Markdown helpers
# ---------------------------------------------------------------------------
def build_model_section_md(model_refs, versions=None):
    if not model_refs:
        return "\n## Confirmed Models in Codebase\n\n_No specific model names detected._\n"
    versions = versions or {}
    lines = ["\n## Confirmed Models in Codebase\n"]
    for model in sorted(model_refs.keys()):
        refs = model_refs[model]
        lines.append(f"\n### `{model}`\n")
        lines.append("| File | Line | Snippet | Link |")
        lines.append("|------|------|---------|------|")
        for r in refs:
            snippet = r["snippet"].replace("|", "\\|")
            # Annotate with dependency version if available
            dep_key = r.get("dep_key", "")
            ver = versions.get(dep_key, "") if dep_key else ""
            ver_note = f" `v{ver}`" if ver else ""
            lines.append(f"| `{r['file']}` | {r['line']} | `{snippet}`{ver_note} | [view]({r['url']}) |")
    return "\n".join(lines)


def build_cve_section_md(cves):
    if not cves:
        return "\n## CVEs Referenced in Codebase\n\n_No CVE IDs detected._\n"
    lines = ["\n## CVEs Referenced in Codebase\n"]
    lines.append("| CVE ID | File | Line | Snippet |")
    lines.append("|--------|------|------|---------|")
    for cve_id in sorted(cves.keys()):
        for r in cves[cve_id]:
            snippet = r["snippet"].replace("|", "\\|")
            nvd = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            lines.append(f"| [{cve_id}]({nvd}) | `{r['file']}` | {r['line']} | `{snippet}` |")
    return "\n".join(lines)


def write_markdown(output_path, repo_url, report_md, model_refs, cves, versions=None):
    repo_name = Path(urlparse(repo_url).path).name
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    header = f"# AI Component Scan: {repo_name}\n\n**Repo:** {repo_url}  \n**Scanned:** {ts}\n\n---\n"
    full = (header + report_md + "\n\n---\n"
            + build_cve_section_md(cves)
            + "\n\n---\n"
            + build_model_section_md(model_refs, versions))
    Path(output_path).write_text(full)
    print(f"Markdown report: {output_path}")


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------
def inline_md(text):
    import html as hl
    text = hl.escape(text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    text = re.sub(r'\[(.+?)\]\((.+?)\)', r'<a href="\2" target="_blank">\1</a>', text)
    return text


def md_to_html(md_text):
    import html as hl
    lines = md_text.split("\n")
    out = []
    in_table = False
    in_code = False
    in_list = False
    first_row = False

    for line in lines:
        if line.strip().startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                if in_list: out.append("</ul>"); in_list = False
                if in_table: out.append("</tbody></table>"); in_table = False
                out.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            out.append(hl.escape(line))
            continue

        if "|" in line and line.strip().startswith("|"):
            if not in_table:
                if in_list: out.append("</ul>"); in_list = False
                out.append('<table class="rt"><thead>')
                in_table = True
                first_row = True
            if re.match(r'^\|[\s\-|]+\|$', line.strip()):
                if first_row:
                    out.append("</thead><tbody>")
                    first_row = False
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            tag = "th" if first_row else "td"
            row = "".join(f"<{tag}>{inline_md(c)}</{tag}>" for c in cells)
            out.append(f"<tr>{row}</tr>")
            if first_row:
                out.append("</thead><tbody>")
                first_row = False
            continue
        else:
            if in_table: out.append("</tbody></table>"); in_table = False

        h = re.match(r'^(#{1,4})\s+(.*)', line)
        if h:
            if in_list: out.append("</ul>"); in_list = False
            level = len(h.group(1))
            text = h.group(2)
            slug = re.sub(r'[^\w\s-]', '', text).strip().lower().replace(" ", "-")
            # number prefix → clean slug
            slug = re.sub(r'^\d+[\.\-]\s*', '', slug)
            out.append(f'<h{level} id="{slug}">{inline_md(text)}</h{level}>')
        elif re.match(r'^[-*]\s+', line):
            if not in_list: out.append("<ul>"); in_list = True
            out.append(f"<li>{inline_md(line[2:])}</li>")
        elif line.strip() == "":
            if in_list: out.append("</ul>"); in_list = False
        else:
            if in_list: out.append("</ul>"); in_list = False
            if line.strip():
                out.append(f"<p>{inline_md(line)}</p>")

    if in_table: out.append("</tbody></table>")
    if in_list: out.append("</ul>")
    return "\n".join(out)


def build_cve_html(cves):
    if not cves:
        return '<p class="muted">No CVE IDs detected in this codebase.</p>'

    STATUS_STYLE = {
        "ACTIVE": ("🔴 ACTIVE", "#f85149", "#2d0f0f"),
        "FIXED":  ("✅ FIXED",  "#3fb950", "#0d1f11"),
        "TEST":   ("🧪 TEST",   "#58a6ff", "#0d1f3c"),
        "DOC":    ("📄 DOC",    "#8b949e", "#1c1c1c"),
    }

    # Group by overall_context for the summary counts
    counts = {"ACTIVE": 0, "FIXED": 0, "TEST": 0, "DOC": 0}
    for refs in cves.values():
        counts[refs[0].get("overall_context", "ACTIVE")] += 1

    summary = " &nbsp;|&nbsp; ".join(
        f'<span style="color:{STATUS_STYLE[s][1]}">{STATUS_STYLE[s][0]} {counts[s]}</span>'
        for s in ("ACTIVE", "FIXED", "TEST", "DOC") if counts[s]
    )

    rows = ""
    for cve_id in sorted(cves.keys()):
        nvd = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        refs = cves[cve_id]
        first = refs[0]
        overall = first.get("overall_context", "ACTIVE")
        label, color, bg = STATUS_STYLE.get(overall, ("UNKNOWN", "#8b949e", "#1c1c1c"))
        snippet = first["snippet"].replace("<", "&lt;").replace(">", "&gt;")
        extra = f" <span class='muted'>(+{len(refs)-1} more)</span>" if len(refs) > 1 else ""
        # For FIXED/DOC rows, dim the CVE link colour
        link_style = f"color:{color}!important" if overall != "ACTIVE" else ""
        rows += f"""<tr style="background:{bg}08">
          <td><a class="cve-link" href="{nvd}" target="_blank" style="{link_style}">{cve_id}</a></td>
          <td><span style="color:{color};font-weight:700;font-size:.8rem;background:{bg};padding:2px 7px;border-radius:10px;border:1px solid {color}40">{label}</span></td>
          <td><code>{first['file']}</code> L{first['line']}{extra}</td>
          <td><code>{snippet[:100]}</code></td>
          <td><a href="{first['url']}" target="_blank">view →</a></td>
        </tr>"""
    return (
        f'<div style="margin-bottom:10px;font-size:.85rem">{summary}</div>'
        + f'<table class="rt"><thead><tr><th>CVE</th><th>Status</th><th>Location</th><th>Snippet</th><th>Code</th></tr></thead><tbody>{rows}</tbody></table>'
    )


# Map model name prefixes to their SDK package name
_MODEL_SDK_MAP = {
    "gpt":     ["openai"],
    "claude":  ["anthropic"],
    "gemini":  ["google-generativeai", "google-genai"],
    "mistral": ["mistralai"],
    "llama":   ["litellm", "llama-index", "llama_index"],
    "mixtral": ["litellm"],
    "command": ["cohere"],
    "titan":   ["boto3", "aioboto3"],
    "nova":    ["boto3", "aioboto3"],
}

def _sdk_version_for_model(model_name, versions):
    """Return a badge string like openai v1.100.1 for a model, or empty string."""
    ml = model_name.lower()
    for prefix, pkgs in _MODEL_SDK_MAP.items():
        if ml.startswith(prefix):
            for pkg in pkgs:
                ver = versions.get(pkg)
                if ver:
                    return f'<span style="color:#58a6ff;font-size:.75rem;margin-left:8px;background:#0d1f3c;padding:2px 8px;border-radius:10px">{pkg} v{ver}</span>'
    return ""


def build_model_html(model_refs, versions=None):
    if not model_refs:
        return "<p class='muted'>No specific model names detected.</p>"
    versions = versions or {}
    html = []
    for model in sorted(model_refs.keys()):
        refs = model_refs[model]
        sdk_badge = _sdk_version_for_model(model, versions)
        rows = ""
        for r in refs:
            snippet = r["snippet"].replace("<", "&lt;").replace(">", "&gt;")
            rows += f"""<tr>
              <td><code>{r['file']}</code></td>
              <td>{r['line']}</td>
              <td><code>{snippet}</code></td>
              <td><a href="{r['url']}" target="_blank">view →</a></td>
            </tr>"""
        html.append(f"""<div class="model-card">
          <div class="model-name">🤖 {model}{sdk_badge}</div>
          <table class="rt"><thead><tr><th>File</th><th>Line</th><th>Snippet</th><th>Link</th></tr></thead>
          <tbody>{rows}</tbody></table>
        </div>""")
    return "\n".join(html)


def build_toc_html(model_count, cve_count, topo_filename=None):
    items = ""
    for slug, label in SECTIONS:
        if slug == "ai-topology":
            if topo_filename:
                items += f'<li><a href="{topo_filename}" target="_blank">🗺️ {label} ↗</a></li>\n'
            continue
        icon = "🔒" if "security" in slug or "cve" in slug else (
               "🤖" if "model" in slug else "📦")
        items += f'<li><a href="#{slug}">{icon} {label}</a></li>\n'
    topo_link = f'<li><a href="{topo_filename}" target="_blank">🗺️ AI System Topology ↗</a></li>\n' if topo_filename else ""
    return f"""<nav class="toc">
      <div class="toc-title">Contents</div>
      <ul>
        <li><a href="#cve-panel">🚨 CVEs ({cve_count} found)</a></li>
        {items}
        {topo_link}
      </ul>
    </nav>"""


def write_html(output_path, repo_url, report_md, model_refs, cves, bom_html="", topo_filename=None, versions=None):
    repo_name = Path(urlparse(repo_url).path).name
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    report_html = md_to_html(report_md)
    cve_html = build_cve_html(cves)
    model_html = build_model_html(model_refs, versions)
    toc_html = build_toc_html(len(model_refs), len(cves), topo_filename)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AI Scan: {repo_name}</title>
<style>
:root{{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --green:#3fb950;--yellow:#d29922;--red:#f85149;--orange:#e3702e;
  --model:#7ee787;--model-bg:#0f2a0f;
  --cve:#f85149;--cve-bg:#2d0f0f;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.6;display:flex;flex-direction:column;min-height:100vh}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
code{{background:var(--surface2);color:#79c0ff;padding:2px 6px;border-radius:4px;font-size:.85em;font-family:'SF Mono',Monaco,monospace}}
pre{{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:16px;overflow-x:auto;margin:12px 0}}
pre code{{background:none;color:#e6edf3;padding:0}}

/* Header */
.header{{background:var(--surface);border-bottom:1px solid var(--border);padding:20px 32px}}
.header h1{{font-size:1.5rem;color:var(--accent)}}
.header .meta{{color:var(--muted);font-size:.85rem;margin-top:4px}}
.badges{{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}}
.badge{{padding:4px 12px;border-radius:20px;font-size:.78rem;font-weight:700;cursor:pointer}}
.badge-cve{{background:var(--cve-bg);color:var(--cve);border:1px solid var(--cve)}}
.badge-model{{background:var(--model-bg);color:var(--model);border:1px solid var(--model)}}
.badge-warn{{background:#2d1a00;color:var(--yellow);border:1px solid var(--yellow)}}

/* Layout */
.layout{{display:flex;flex:1;max-width:1400px;width:100%;margin:0 auto;padding:24px 32px;gap:32px}}

/* TOC sidebar */
.toc{{position:sticky;top:24px;width:220px;flex-shrink:0;align-self:flex-start}}
.toc-title{{font-size:.7rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:10px}}
.toc ul{{list-style:none;border-left:2px solid var(--border);padding-left:12px}}
.toc li{{margin-bottom:6px}}
.toc a{{color:var(--muted);font-size:.85rem;display:block;padding:2px 0;transition:color .15s}}
.toc a:hover{{color:var(--text);text-decoration:none}}

/* Main content */
.main{{flex:1;min-width:0}}

/* CVE panel */
.cve-panel{{background:var(--cve-bg);border:1px solid var(--cve);border-radius:8px;padding:20px;margin-bottom:28px}}
.cve-panel h2{{color:var(--cve);font-size:1.1rem;margin-bottom:14px;display:flex;align-items:center;gap:8px}}
.cve-link{{color:var(--cve)!important;font-weight:700;font-family:'SF Mono',Monaco,monospace}}

/* Report body */
.report-body h1{{font-size:1.5rem;color:var(--accent);margin:32px 0 12px;border-bottom:1px solid var(--border);padding-bottom:8px;scroll-margin-top:24px}}
.report-body h2{{font-size:1.15rem;color:var(--text);margin:28px 0 10px;scroll-margin-top:24px}}
.report-body h3{{font-size:1rem;color:var(--accent);margin:18px 0 8px;scroll-margin-top:24px}}
.report-body h4{{font-size:.9rem;color:var(--muted);margin:12px 0 6px}}
.report-body p{{margin-bottom:10px}}
.report-body ul{{margin:8px 0 12px 24px}}
.report-body li{{margin-bottom:4px}}
.report-body strong{{color:#f0f6fc}}

/* Tables */
table.rt{{width:100%;border-collapse:collapse;margin:12px 0;font-size:.88rem}}
table.rt th{{background:var(--surface2);color:var(--muted);padding:8px 12px;border:1px solid var(--border);text-align:left;font-weight:600}}
table.rt td{{padding:8px 12px;border:1px solid var(--border);vertical-align:top;word-break:break-word}}
table.rt tr:hover td{{background:var(--surface2)}}

/* Models section */
.models-section{{margin-top:36px}}
.models-section>h2{{font-size:1.2rem;color:var(--model);margin-bottom:16px;border-bottom:1px solid var(--model-bg);padding-bottom:8px;scroll-margin-top:24px}}
.model-card{{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--model);border-radius:8px;margin-bottom:16px;overflow:hidden}}
.model-name{{background:var(--model-bg);color:var(--model);font-family:'SF Mono',Monaco,monospace;font-size:.95rem;font-weight:700;padding:10px 16px}}

.muted{{color:var(--muted)}}
footer{{text-align:center;color:var(--muted);font-size:.78rem;padding:24px;border-top:1px solid var(--border)}}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 AI Component Scan — {repo_name}</h1>
  <div class="meta"><a href="{repo_url}" target="_blank">{repo_url}</a> &nbsp;·&nbsp; Scanned {ts}</div>
  <div class="badges">
    <a href="#cve-panel"><span class="badge badge-cve">🚨 {sum(1 for v in cves.values() if v[0].get("overall_context","ACTIVE")=="ACTIVE")} active CVEs ({len(cves)} total)</span></a>
    <a href="#confirmed-models"><span class="badge badge-model">🤖 {len(model_refs)} models confirmed in source</span></a>
    <a href="#security-concerns"><span class="badge badge-warn">⚠️ Security Concerns</span></a>
  </div>
</div>

<div class="layout">
  {toc_html}

  <div class="main">

    <!-- CVE Panel -->
    <div class="cve-panel" id="cve-panel">
      <h2>🚨 CVEs Referenced in Codebase <span style="font-size:.8rem;font-weight:400;color:var(--muted)">({len(cves)} unique IDs — 🔴 {sum(1 for v in cves.values() if v[0].get("overall_context","ACTIVE")=="ACTIVE")} active, ✅ {sum(1 for v in cves.values() if v[0].get("overall_context","ACTIVE")=="FIXED")} fixed)</span></h2>
      {cve_html}
    </div>

    <!-- Report -->
    <div class="report-body">
      {report_html}
    </div>

    <!-- Models -->
    <div class="models-section" id="confirmed-models">
      <h2>🤖 Confirmed Models in Codebase</h2>
      <p class="muted" style="font-size:.85rem;margin-bottom:16px">
        Model names detected directly in source files — click any row to jump to the exact location.
      </p>
      {model_html}
    </div>

  </div>
</div>

<footer>Generated by claudescan &nbsp;·&nbsp; Powered by Claude Opus 4.6</footer>
</body>
</html>"""

    html = html.replace('{bom_html}', bom_html)
    Path(output_path).write_text(html)
    print(f"HTML report:     {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def write_github_summary(md_path, model_refs, cves):
    """Write rendered Markdown to GitHub Actions job summary (max 1024k)."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    MAX = 1_000_000  # stay under GitHub's 1024k limit
    report = Path(md_path).read_text()
    if len(report) > MAX:
        report = report[:MAX] + "\n\n> ⚠️ Report truncated to fit GitHub summary limit. Download the artifact for the full report.\n"
    with open(summary_file, "a") as f:
        f.write(report)
    print(f"  → Written to GitHub job summary ({len(report):,} chars).")


def _git_remote_url(repo_dir):
    """Try to get the remote URL from git config."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, cwd=repo_dir,
        )
        if result.returncode == 0:
            url = result.stdout.strip().rstrip("/")
            # Convert SSH to HTTPS
            if url.startswith("git@"):
                url = url.replace(":", "/").replace("git@", "https://")
            if url.endswith(".git"):
                url = url[:-4]
            return url
    except Exception:
        pass
    return None


def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY is not set.", file=sys.stderr)
        sys.exit(1)

    in_ci = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))

    repo_dir = str(Path(__file__).parent.resolve())
    repo_url = _git_remote_url(repo_dir) or f"file://{repo_dir}"
    repo_name = Path(repo_dir).name
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(repo_dir) / "reports"
    out_dir.mkdir(exist_ok=True)

    try:
        print(f"Scanning {repo_dir}\n", flush=True)

        print("Scanning for model references...", flush=True)
        model_refs = find_model_references(repo_dir, repo_url)
        print(f"  → {len(model_refs)} distinct model names found.", flush=True)

        print("Scanning for CVE references...", flush=True)
        cves = find_cves(repo_dir, repo_url)
        print(f"  → {len(cves)} unique CVE IDs found.", flush=True)

        print("\nCollecting AI-relevant files...", flush=True)
        content = collect_repo_content(repo_dir)
        print(f"  → {len(content):,} chars collected.\n", flush=True)
        print("=" * 70)

        report_md = analyze_with_claude(repo_url, content)

        print("=" * 70)
        print("\nWriting reports...", flush=True)

        md_path   = out_dir / f"{repo_name}_{ts}.md"
        html_path = out_dir / f"{repo_name}_{ts}.html"

        print("Building AI-BOM...", flush=True)
        versions = parse_versions_from_requirements(repo_dir)
        bom = build_aibom(repo_url, repo_dir, model_refs, cves, versions)
        bom_html = build_aibom_html_section(bom)
        bom_path = out_dir / f"{repo_name}_{ts}_bom.json"
        write_aibom(str(bom_path), bom)

        # Build AI system topology diagram
        topo_path = out_dir / f"{repo_name}_{ts}_topology.html"
        topo_filename = None
        print("\nBuilding AI system topology diagram...", flush=True)
        try:
            topo_prompt = build_topology_prompt(repo_url, content)
            client_topo = anthropic.Anthropic()
            topo_response = ""
            with client_topo.messages.stream(
                model="claude-opus-4-6",
                max_tokens=16000,
                messages=[{"role": "user", "content": topo_prompt}],
            ) as stream:
                for text in stream.text_stream:
                    topo_response += text
            topo_data = extract_json_from_response(topo_response)
            if not topo_data or not isinstance(topo_data, dict):
                print(f"  ⚠ Could not parse topology JSON — raw response:\n{topo_response[:300]}", flush=True)
            elif not topo_data.get("nodes"):
                print("  ⚠ Topology JSON parsed but has no nodes.", flush=True)
            else:
                write_topology(str(topo_path), topo_data, repo_url, repo_name, ts)
                topo_filename = topo_path.name
                print(f"  → Topology diagram: {topo_filename}", flush=True)
        except Exception as e:
            import traceback
            print(f"  ⚠ Topology generation failed: {e}", flush=True)
            traceback.print_exc()

        write_markdown(str(md_path), repo_url, report_md, model_refs, cves, versions)
        write_html(str(html_path), repo_url, report_md, model_refs, cves, bom_html, topo_filename, versions)

        if in_ci:
            print("\nRendering to GitHub job summary...", flush=True)
            write_github_summary(str(md_path), model_refs, cves)
        else:
            print(f"\nOpening in browser...")
            webbrowser.open(f"file://{html_path.absolute()}")

    finally:
        pass


if __name__ == "__main__":
    main()
