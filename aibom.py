#!/usr/bin/env python3
"""
aibom.py - AI Bill of Materials generator (CycloneDX 1.7 + OWASP AI BOM extensions)
"""

import json
import re
import uuid
import requests
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Known AI component metadata: license, type, supplier, purpose
# ---------------------------------------------------------------------------
AI_COMPONENT_META = {
    # LLM SDKs
    "openai":            {"license": "Apache-2.0", "supplier": "OpenAI",          "type": "library", "purpose": "llm-integration"},
    "anthropic":         {"license": "MIT",        "supplier": "Anthropic",        "type": "library", "purpose": "llm-integration"},
    "google-generativeai":{"license":"Apache-2.0", "supplier": "Google",           "type": "library", "purpose": "llm-integration"},
    "google-genai":      {"license": "Apache-2.0", "supplier": "Google",           "type": "library", "purpose": "llm-integration"},
    "google-cloud-aiplatform":{"license":"Apache-2.0","supplier":"Google",         "type": "library", "purpose": "llm-integration"},
    "cohere":            {"license": "MIT",        "supplier": "Cohere",           "type": "library", "purpose": "llm-integration"},
    "mistralai":         {"license": "Apache-2.0", "supplier": "Mistral AI",       "type": "library", "purpose": "llm-integration"},
    "groq":              {"license": "Apache-2.0", "supplier": "Groq",             "type": "library", "purpose": "llm-integration"},
    "together":          {"license": "Apache-2.0", "supplier": "Together AI",      "type": "library", "purpose": "llm-integration"},
    "replicate":         {"license": "Apache-2.0", "supplier": "Replicate",        "type": "library", "purpose": "llm-integration"},
    "litellm":           {"license": "MIT",        "supplier": "BerriAI",          "type": "library", "purpose": "llm-proxy"},
    # Orchestration
    "langchain":         {"license": "MIT",        "supplier": "LangChain",        "type": "library", "purpose": "orchestration"},
    "langchain-core":    {"license": "MIT",        "supplier": "LangChain",        "type": "library", "purpose": "orchestration"},
    "langchain-community":{"license":"MIT",        "supplier": "LangChain",        "type": "library", "purpose": "orchestration"},
    "langsmith":         {"license": "MIT",        "supplier": "LangChain",        "type": "library", "purpose": "observability"},
    "llama-index":       {"license": "MIT",        "supplier": "LlamaIndex",       "type": "library", "purpose": "orchestration"},
    "llama_index":       {"license": "MIT",        "supplier": "LlamaIndex",       "type": "library", "purpose": "orchestration"},
    "haystack-ai":       {"license": "Apache-2.0", "supplier": "deepset",          "type": "library", "purpose": "orchestration"},
    "semantic-router":   {"license": "MIT",        "supplier": "Aurelio AI",       "type": "library", "purpose": "routing"},
    "mcp":               {"license": "MIT",        "supplier": "Anthropic",        "type": "library", "purpose": "agent-protocol"},
    "a2a-sdk":           {"license": "Apache-2.0", "supplier": "Google",           "type": "library", "purpose": "agent-protocol"},
    # ML frameworks
    "torch":             {"license": "BSD-3-Clause","supplier":"Meta",             "type": "library", "purpose": "ml-framework"},
    "tensorflow":        {"license": "Apache-2.0", "supplier": "Google",           "type": "library", "purpose": "ml-framework"},
    "keras":             {"license": "Apache-2.0", "supplier": "Google",           "type": "library", "purpose": "ml-framework"},
    "jax":               {"license": "Apache-2.0", "supplier": "Google",           "type": "library", "purpose": "ml-framework"},
    "transformers":      {"license": "Apache-2.0", "supplier": "Hugging Face",     "type": "library", "purpose": "ml-framework"},
    "huggingface-hub":   {"license": "Apache-2.0", "supplier": "Hugging Face",     "type": "library", "purpose": "model-registry"},
    "tokenizers":        {"license": "Apache-2.0", "supplier": "Hugging Face",     "type": "library", "purpose": "tokenization"},
    "diffusers":         {"license": "Apache-2.0", "supplier": "Hugging Face",     "type": "library", "purpose": "generative-image"},
    "scikit-learn":      {"license": "BSD-3-Clause","supplier":"scikit-learn",     "type": "library", "purpose": "ml-framework"},
    "sklearn":           {"license": "BSD-3-Clause","supplier":"scikit-learn",     "type": "library", "purpose": "ml-framework"},
    "spacy":             {"license": "MIT",        "supplier": "Explosion",        "type": "library", "purpose": "nlp"},
    "nltk":              {"license": "Apache-2.0", "supplier": "NLTK",             "type": "library", "purpose": "nlp"},
    # Embeddings & Vector DBs
    "pinecone-client":   {"license": "Apache-2.0", "supplier": "Pinecone",         "type": "library", "purpose": "vector-db"},
    "pinecone":          {"license": "Apache-2.0", "supplier": "Pinecone",         "type": "library", "purpose": "vector-db"},
    "weaviate-client":   {"license": "BSD-3-Clause","supplier":"Weaviate",         "type": "library", "purpose": "vector-db"},
    "chromadb":          {"license": "Apache-2.0", "supplier": "Chroma",           "type": "library", "purpose": "vector-db"},
    "faiss-cpu":         {"license": "MIT",        "supplier": "Meta",             "type": "library", "purpose": "vector-search"},
    "faiss-gpu":         {"license": "MIT",        "supplier": "Meta",             "type": "library", "purpose": "vector-search"},
    "qdrant-client":     {"license": "Apache-2.0", "supplier": "Qdrant",           "type": "library", "purpose": "vector-db"},
    "pymilvus":          {"license": "Apache-2.0", "supplier": "Zilliz",           "type": "library", "purpose": "vector-db"},
    "redisvl":           {"license": "MIT",        "supplier": "Redis",            "type": "library", "purpose": "vector-db"},
    "tiktoken":          {"license": "MIT",        "supplier": "OpenAI",           "type": "library", "purpose": "tokenization"},
    # Observability / MLOps
    "mlflow":            {"license": "Apache-2.0", "supplier": "Databricks",       "type": "library", "purpose": "mlops"},
    "wandb":             {"license": "MIT",        "supplier": "Weights & Biases", "type": "library", "purpose": "mlops"},
    "langfuse":          {"license": "MIT",        "supplier": "Langfuse",         "type": "library", "purpose": "observability"},
    "boto3":             {"license": "Apache-2.0", "supplier": "Amazon",           "type": "library", "purpose": "cloud-ai"},
    "aioboto3":          {"license": "Apache-2.0", "supplier": "Amazon",           "type": "library", "purpose": "cloud-ai"},
}

# PyPI PURL ecosystem override (npm packages would use "npm")
PKG_ECOSYSTEM = {
    "a2a-sdk": "npm",
}

# EU AI Act risk tiers by purpose
EU_AI_ACT_RISK = {
    "llm-integration":   "high",
    "llm-proxy":         "high",
    "orchestration":     "high",
    "agent-protocol":    "high",
    "generative-image":  "high",
    "ml-framework":      "limited",
    "nlp":               "limited",
    "vector-db":         "minimal",
    "vector-search":     "minimal",
    "tokenization":      "minimal",
    "routing":           "limited",
    "observability":     "minimal",
    "mlops":             "minimal",
    "cloud-ai":          "limited",
    "model-registry":    "limited",
}

# GDPR relevance by purpose
GDPR_RELEVANT = {"llm-integration", "llm-proxy", "orchestration", "agent-protocol"}

# Well-known model suppliers for PURL generation
MODEL_SUPPLIERS = {
    "gpt":       ("OpenAI",       "openai"),
    "claude":    ("Anthropic",    "anthropic"),
    "gemini":    ("Google",       "google"),
    "mistral":   ("Mistral AI",   "mistral-ai"),
    "llama":     ("Meta",         "meta"),
    "mixtral":   ("Mistral AI",   "mistral-ai"),
    "deepseek":  ("DeepSeek",     "deepseek"),
    "qwen":      ("Alibaba",      "alibaba"),
    "command":   ("Cohere",       "cohere"),
    "titan":     ("Amazon",       "amazon"),
    "nova":      ("Amazon",       "amazon"),
}


def _model_supplier(model_name):
    """Return (supplier_name, supplier_slug) for a model name."""
    ml = model_name.lower()
    for prefix, (name, slug) in MODEL_SUPPLIERS.items():
        if ml.startswith(prefix):
            return name, slug
    return "Unknown", "unknown"


def _model_purl(model_name):
    """Generate a best-effort PURL for a model reference."""
    _, slug = _model_supplier(model_name)
    safe = re.sub(r'[^a-zA-Z0-9._\-]', '-', model_name)
    return f"pkg:mlmodel/{slug}/{safe}"


def parse_versions_from_requirements(repo_dir):
    """Extract package->version from requirements.txt, pyproject.toml, package.json."""
    versions = {}
    root = Path(repo_dir)

    # requirements.txt style
    for fname in ["requirements.txt", "requirements-dev.txt", ".circleci/requirements.txt"]:
        f = root / fname
        if f.exists():
            for line in f.read_text(errors="replace").splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*[=~><!\^]+\s*([\w\.\*]+)', line)
                if m:
                    pkg = m.group(1).lower().replace("_", "-")
                    versions[pkg] = m.group(2)

    # pyproject.toml
    f = root / "pyproject.toml"
    if f.exists():
        for line in f.read_text(errors="replace").splitlines():
            m = re.match(r'^\s*([A-Za-z0-9_\-\.]+)\s*=\s*["\^~>=<!\s]*([\d\w\.]+)', line)
            if m:
                pkg = m.group(1).lower().replace("_", "-")
                if pkg not in versions:
                    versions[pkg] = m.group(2)

    # package.json
    f = root / "package.json"
    if f.exists():
        try:
            data = json.loads(f.read_text(errors="replace"))
            for section in ["dependencies", "devDependencies"]:
                for pkg, ver in data.get(section, {}).items():
                    clean_ver = re.sub(r'^[^\d]*', '', ver)
                    versions[pkg.lower()] = clean_ver
        except Exception:
            pass

    return versions


def query_osv(package_name, version, ecosystem="PyPI"):
    """Query OSV API for known vulnerabilities."""
    try:
        payload = {
            "version": version,
            "package": {"name": package_name, "ecosystem": ecosystem}
        }
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            return [
                {
                    "id": v.get("id", ""),
                    "summary": v.get("summary", "")[:120],
                    "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
                    "url": f"https://osv.dev/vulnerability/{v.get('id', '')}",
                }
                for v in vulns[:5]
            ]
    except Exception:
        pass
    return []


def build_aibom(repo_url, repo_dir, model_refs, cves, versions):
    """Build a CycloneDX 1.7 AI-BOM JSON document."""
    parsed = urlparse(repo_url)
    repo_name = Path(parsed.path).name.replace(".git", "") or "repo"
    repo_org  = parsed.path.strip("/").split("/")[0] if parsed.path.count("/") >= 1 else "unknown"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bom_serial = f"urn:uuid:{uuid.uuid4()}"

    # Root application component (the scanned repo)
    if "github.com" in repo_url:
        root_purl = f"pkg:github/{repo_org}/{repo_name}@main"
    elif "gitlab.com" in repo_url:
        root_purl = f"pkg:gitlab/{repo_org}/{repo_name}@main"
    else:
        root_purl = f"pkg:generic/{repo_name}@main"

    root_ref = f"root-{repo_name}"

    metadata_component = {
        "type": "application",
        "bom-ref": root_ref,
        "supplier": {"name": repo_org},
        "name": repo_name,
        "version": "main",
        "purl": root_purl,
        "description": f"Scanned repository: {repo_url}",
    }

    components = []
    vulnerabilities = []
    dependency_refs = []   # refs of direct deps for the root component

    print("  Building AI-BOM components...", flush=True)

    for pkg_name, meta in AI_COMPONENT_META.items():
        version = versions.get(pkg_name) or versions.get(pkg_name.replace("-", "_")) or "unknown"
        if version == "unknown":
            continue  # only include packages actually present in the repo

        ecosystem = PKG_ECOSYSTEM.get(pkg_name, "PyPI")
        comp_ref = f"comp-{pkg_name}"
        purpose  = meta["purpose"]

        # Build PURL
        safe_ver = re.sub(r'[^a-zA-Z0-9._\-]', '', version)
        if ecosystem == "PyPI":
            purl = f"pkg:pypi/{pkg_name}@{safe_ver}"
        elif ecosystem == "npm":
            purl = f"pkg:npm/{pkg_name}@{safe_ver}"
        else:
            purl = f"pkg:generic/{pkg_name}@{safe_ver}"

        # Query OSV for CVEs
        vulns = []
        print(f"    Checking OSV: {pkg_name}=={version}", flush=True)
        vulns = query_osv(pkg_name, version, ecosystem)

        component = {
            "type": meta["type"],
            "bom-ref": comp_ref,
            "supplier": {"name": meta["supplier"]},
            "name": pkg_name,
            "version": version,
            "purl": purl,
            "licenses": [{"license": {"id": meta["license"]}}],
            "properties": [
                {"name": "ai:purpose",         "value": purpose},
                {"name": "ai:eu-ai-act-risk",  "value": EU_AI_ACT_RISK.get(purpose, "unknown")},
                {"name": "ai:gdpr-relevant",   "value": str(purpose in GDPR_RELEVANT).lower()},
                {"name": "ai:soc2-relevant",   "value": "true" if purpose in {"llm-integration", "llm-proxy", "orchestration"} else "false"},
            ],
        }
        components.append(component)
        dependency_refs.append(comp_ref)

        for v in vulns:
            vulnerabilities.append({
                "bom-ref": str(uuid.uuid4()),
                "id": v["id"],
                "source": {"url": v["url"], "name": "OSV"},
                "ratings": [{"severity": v["severity"].lower() if v["severity"] != "UNKNOWN" else "unknown"}],
                "description": v["summary"],
                "affects": [{"ref": comp_ref}],
            })

    # Add confirmed models as machine-learning-model components
    for model_name, refs in model_refs.items():
        first = refs[0]
        supplier_name, supplier_slug = _model_supplier(model_name)
        model_ref = f"model-{re.sub(r'[^a-zA-Z0-9._-]', '-', model_name)[:40]}"
        components.append({
            "type": "machine-learning-model",
            "bom-ref": model_ref,
            "supplier": {"name": supplier_name},
            "name": model_name,
            "version": "unknown",
            "purl": _model_purl(model_name),
            "properties": [
                {"name": "ai:purpose",        "value": "inference"},
                {"name": "ai:confirmed-in",   "value": first["file"]},
                {"name": "ai:source-url",     "value": first["url"]},
                {"name": "ai:eu-ai-act-risk", "value": "high"},
                {"name": "ai:gdpr-relevant",  "value": "true"},
            ],
        })
        dependency_refs.append(model_ref)

    # Build dependency graph: root depends on all detected components
    # Each library component has no further declared deps (we don't have transitive data)
    dependencies = [
        {"ref": root_ref, "dependsOn": dependency_refs}
    ] + [
        {"ref": c["bom-ref"], "dependsOn": []}
        for c in components
    ]

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "lifecycles": [{"phase": "runtime"}],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "supplier": {"name": "claudescan"},
                        "name": "claudescan",
                        "version": "1.0.0",
                        "purl": "pkg:github/rlfagan/aiscan@main",
                    }
                ]
            },
            "authors": [{"name": "claudescan AI Scanner", "email": "noreply@claudescan"}],
            "component": metadata_component,
            "properties": [
                {"name": "ai:scan-date",              "value": ts},
                {"name": "ai:repo-url",               "value": repo_url},
                {"name": "ai:total-cves-in-code",     "value": str(len(cves))},
                {"name": "ai:total-models-detected",  "value": str(len(model_refs))},
            ],
        },
        "components": components,
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities,
    }

    return bom


def write_aibom(output_path, bom):
    Path(output_path).write_text(json.dumps(bom, indent=2))
    comp_count = len(bom["components"])
    vuln_count = len(bom["vulnerabilities"])
    dep_count  = len(bom["dependencies"])
    print(f"AI-BOM (CycloneDX 1.7): {output_path}")
    print(f"  → {comp_count} components, {dep_count} dependency entries, {vuln_count} OSV vulnerabilities")


def build_aibom_html_section(bom):
    """Build an HTML summary section for the AI-BOM to embed in the main report."""
    components = bom["components"]
    vulns = bom["vulnerabilities"]

    risk_counts = {"high": 0, "limited": 0, "minimal": 0, "unknown": 0}
    for c in components:
        for p in c.get("properties", []):
            if p["name"] == "ai:eu-ai-act-risk":
                risk_counts[p["value"]] = risk_counts.get(p["value"], 0) + 1

    rows = ""
    for c in components:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        risk = props.get("ai:eu-ai-act-risk", "unknown")
        risk_color = {"high": "#f85149", "limited": "#d29922", "minimal": "#3fb950"}.get(risk, "#8b949e")
        gdpr = "⚠️ Yes" if props.get("ai:gdpr-relevant") == "true" else "No"
        comp_vulns = [v for v in vulns if any(a["ref"] == c["bom-ref"] for a in v.get("affects", []))]
        vuln_badge = (
            f'<span style="color:#f85149;font-weight:700">{len(comp_vulns)} CVE{"s" if len(comp_vulns)!=1 else ""}</span>'
            if comp_vulns else '<span style="color:#3fb950">Clean</span>'
        )
        purl = c.get("purl", "")
        purl_display = f'<code style="font-size:.7rem">{purl[:50]}{"…" if len(purl)>50 else ""}</code>' if purl else "—"
        rows += f"""<tr>
          <td><code>{c['name']}</code></td>
          <td>{c.get('version','?')}</td>
          <td>{c.get('supplier',{}).get('name','?')}</td>
          <td>{props.get('ai:purpose','?')}</td>
          <td><span style="color:{risk_color};font-weight:700">{risk.upper()}</span></td>
          <td>{gdpr}</td>
          <td>{vuln_badge}</td>
          <td>{c.get('licenses',[{}])[0].get('license',{}).get('id','?')}</td>
          <td>{purl_display}</td>
        </tr>"""

    return f"""
    <div class="bom-section" id="ai-bom">
      <h2>📋 AI Bill of Materials (CycloneDX 1.7)</h2>
      <div class="bom-stats">
        <div class="bom-stat"><span class="bom-num">{len(components)}</span><span class="bom-label">Components</span></div>
        <div class="bom-stat"><span class="bom-num" style="color:#f85149">{len(vulns)}</span><span class="bom-label">OSV Vulnerabilities</span></div>
        <div class="bom-stat"><span class="bom-num" style="color:#f85149">{risk_counts.get('high',0)}</span><span class="bom-label">EU AI Act High Risk</span></div>
        <div class="bom-stat"><span class="bom-num" style="color:#d29922">{risk_counts.get('limited',0)}</span><span class="bom-label">Limited Risk</span></div>
        <div class="bom-stat"><span class="bom-num" style="color:#3fb950">{risk_counts.get('minimal',0)}</span><span class="bom-label">Minimal Risk</span></div>
      </div>
      <table class="rt">
        <thead><tr><th>Package</th><th>Version</th><th>Supplier</th><th>Purpose</th><th>EU AI Act</th><th>GDPR</th><th>Vulns (OSV)</th><th>License</th><th>PURL</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p style="color:var(--muted);font-size:.8rem;margin-top:8px">
        Full machine-readable BOM: download <code>bom.json</code> artifact (CycloneDX 1.7) &bull;
        Includes dependency graph &bull; All components have PURL &amp; supplier
      </p>
    </div>"""
