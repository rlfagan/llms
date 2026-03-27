#!/usr/bin/env python3
"""
Download the top 10 most popular Hugging Face models (metadata + config only).
Full weights are skipped by default to avoid storing multi-GB files in git.
Set DOWNLOAD_WEIGHTS=1 to fetch full model weights.
"""

import os
import json
import subprocess
from pathlib import Path

TOP10_MODELS = [
    "sentence-transformers/all-MiniLM-L6-v2",
    "google-bert/bert-base-uncased",
    "sentence-transformers/all-mpnet-base-v2",
    "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    "openai/clip-vit-large-patch14",
    "openai/clip-vit-base-patch32",
    "FacebookAI/xlm-roberta-base",
    "google/electra-base-discriminator",
    "Falconsai/nsfw_image_detection",
    "laion/clap-htsat-fused",
]

DOWNLOAD_WEIGHTS = os.environ.get("DOWNLOAD_WEIGHTS", "0") == "1"
OUTPUT_DIR = Path(__file__).parent


def download_model_metadata(model_id: str) -> dict:
    """Fetch model card metadata from HuggingFace Hub API."""
    import urllib.request
    safe_id = model_id.replace("/", "--")
    api_url = f"https://huggingface.co/api/models/{model_id}"
    try:
        with urllib.request.urlopen(api_url, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return {
            "model_id": model_id,
            "author": data.get("author", ""),
            "downloads": data.get("downloads", 0),
            "likes": data.get("likes", 0),
            "pipeline_tag": data.get("pipeline_tag", ""),
            "tags": data.get("tags", []),
            "library_name": data.get("library_name", ""),
            "created_at": data.get("createdAt", ""),
            "last_modified": data.get("lastModified", ""),
        }
    except Exception as e:
        print(f"  [warn] Could not fetch metadata for {model_id}: {e}")
        return {"model_id": model_id, "error": str(e)}


def download_weights(model_id: str, dest: Path):
    """Download full model weights via huggingface_hub."""
    try:
        from huggingface_hub import snapshot_download
        snapshot_download(repo_id=model_id, local_dir=str(dest))
        print(f"  [ok] Weights downloaded to {dest}")
    except ImportError:
        print("  [error] huggingface_hub not installed. Run: pip install huggingface-hub")
    except Exception as e:
        print(f"  [error] Failed to download weights for {model_id}: {e}")


def main():
    index = []
    for model_id in TOP10_MODELS:
        safe_id = model_id.replace("/", "--")
        model_dir = OUTPUT_DIR / safe_id
        model_dir.mkdir(exist_ok=True)

        print(f"Processing {model_id} ...")
        meta = download_model_metadata(model_id)
        meta_path = model_dir / "metadata.json"
        meta_path.write_text(json.dumps(meta, indent=2))
        print(f"  [ok] Metadata saved to {meta_path}")

        if DOWNLOAD_WEIGHTS:
            print(f"  Downloading weights (this may take a while)...")
            download_weights(model_id, model_dir / "weights")

        index.append(meta)

    # Write summary index
    index_path = OUTPUT_DIR / "index.json"
    index_path.write_text(json.dumps(index, indent=2))
    print(f"\nIndex written to {index_path}")
    print(f"\nDone. {len(TOP10_MODELS)} models processed.")
    if not DOWNLOAD_WEIGHTS:
        print("Tip: set DOWNLOAD_WEIGHTS=1 to fetch full model weights.")


if __name__ == "__main__":
    main()
