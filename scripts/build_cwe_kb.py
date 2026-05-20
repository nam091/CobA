"""Build (or refresh) the CobA CWE knowledge base in ChromaDB.

By default, this script reads ``src/coba/data/cwe_top25.json`` — a small
bundled corpus that ships with CobA so the prototype works offline. You can
point ``--source`` at any JSON file with the same shape, or pass
``--mitre-xml <cwec.xml>`` to ingest the full MITRE CWE corpus
(https://cwe.mitre.org/data/downloads.html).

Each record is embedded with ``sentence-transformers/all-MiniLM-L6-v2`` and
persisted into the ChromaDB directory configured via ``settings.chroma_persist_dir``
(default: ``.coba_data/chroma``). Re-running the script is safe — the script
uses ChromaDB's ``upsert`` so existing IDs are overwritten.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from coba.config.settings import get_settings
from coba.utils.logging import configure_logging, get_logger

log = get_logger("coba.scripts.build_cwe_kb")

COLLECTION_NAME = "coba_cwe"
DEFAULT_SOURCE = Path(__file__).resolve().parents[1] / "src" / "coba" / "data" / "cwe_top25.json"


def _load_json(path: Path) -> list[dict[str, Any]]:
    log.info("cwe_kb.load_json", path=str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a JSON list, got {type(data).__name__}")
    return data


def _load_mitre_xml(path: Path) -> list[dict[str, Any]]:
    """Parse a subset of CWE entries from the MITRE CWE XML.

    The MITRE XML is large and richly structured; we extract only the fields
    we use for retrieval (id, name, description, taxonomies) and skip the
    structural relationships, view membership, etc.
    """
    log.info("cwe_kb.load_mitre_xml", path=str(path))
    tree = ET.parse(path)
    root = tree.getroot()
    # MITRE namespace prefix varies between releases.
    ns_match = root.tag.split("}", 1)
    ns = {"c": ns_match[0].lstrip("{")} if len(ns_match) == 2 and root.tag.startswith("{") else {}
    weakness_xpath = ".//c:Weakness" if ns else ".//Weakness"
    desc_xpath = "c:Description" if ns else "Description"
    ext_desc_xpath = "c:Extended_Description" if ns else "Extended_Description"

    out: list[dict[str, Any]] = []
    for w in root.findall(weakness_xpath, ns):
        cwe_id = w.attrib.get("ID")
        name = w.attrib.get("Name")
        if not cwe_id or not name:
            continue
        desc_node = w.find(desc_xpath, ns)
        ext_node = w.find(ext_desc_xpath, ns)
        desc_parts: list[str] = []
        if desc_node is not None and desc_node.text:
            desc_parts.append(desc_node.text.strip())
        if ext_node is not None and ext_node.text:
            desc_parts.append(ext_node.text.strip())
        out.append(
            {
                "cwe_id": f"CWE-{cwe_id}",
                "name": name,
                "description": " ".join(desc_parts),
                "languages": [],
                "owasp": None,
            }
        )
    log.info("cwe_kb.parsed_mitre", count=len(out))
    return out


def _doc_text(entry: dict[str, Any]) -> str:
    parts = [
        f"{entry['cwe_id']} — {entry.get('name', '')}",
        entry.get("description", ""),
    ]
    langs = entry.get("languages")
    if langs:
        parts.append(f"Languages: {', '.join(langs)}.")
    owasp = entry.get("owasp")
    if owasp:
        parts.append(f"OWASP mapping: {owasp}.")
    return "\n".join(p for p in parts if p)


def _connect_chroma(persist_dir: Path):  # type: ignore[no-untyped-def]
    import chromadb
    from chromadb.config import Settings as ChromaSettings

    persist_dir.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(
        path=str(persist_dir),
        settings=ChromaSettings(anonymized_telemetry=False),
    )
    return client


def build(entries: list[dict[str, Any]], persist_dir: Path, embedding_model: str) -> None:
    if not entries:
        raise SystemExit("no CWE entries to ingest")
    client = _connect_chroma(persist_dir)

    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

    embedder = SentenceTransformerEmbeddingFunction(model_name=embedding_model)
    collection = client.get_or_create_collection(COLLECTION_NAME, embedding_function=embedder)

    ids = [e["cwe_id"] for e in entries]
    documents = [_doc_text(e) for e in entries]
    metadatas = [
        {
            "cwe_id": e["cwe_id"],
            "name": e.get("name", ""),
            "languages": ",".join(e.get("languages") or []),
            "owasp": e.get("owasp") or "",
        }
        for e in entries
    ]
    log.info(
        "cwe_kb.upsert",
        collection=COLLECTION_NAME,
        count=len(ids),
        persist_dir=str(persist_dir),
    )
    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the CobA CWE knowledge base.")
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="Path to a JSON file shaped like cwe_top25.json (default: bundled corpus).",
    )
    parser.add_argument(
        "--mitre-xml",
        type=Path,
        default=None,
        help="Path to a MITRE CWE XML file (cwec_v*.xml). Overrides --source.",
    )
    parser.add_argument(
        "--persist-dir",
        type=Path,
        default=None,
        help="Override Chroma persist dir (default: settings.chroma_persist_dir).",
    )
    parser.add_argument(
        "--embedding-model",
        type=str,
        default=None,
        help="Override the embedding model name (default: settings.embedding_model).",
    )
    args = parser.parse_args(argv)

    configure_logging()
    settings = get_settings()
    persist_dir = args.persist_dir or settings.chroma_persist_dir
    embedding_model = args.embedding_model or settings.embedding_model

    entries = _load_mitre_xml(args.mitre_xml) if args.mitre_xml else _load_json(args.source)

    build(entries, persist_dir, embedding_model)
    log.info("cwe_kb.done", count=len(entries), persist_dir=str(persist_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
