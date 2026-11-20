"""Load documents from data/ into a Chroma vector database.

Every document is tagged with an access level ("public" or "confidential")
based on the folder it lives in. Later milestones use this tag for
role-based access control, so a user only retrieves what their role allows.

Run from the project root:
    python -m src.ingest
"""
from pathlib import Path

import chromadb
import ollama

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_DIR = PROJECT_ROOT / "chroma_db"
COLLECTION = "security_docs"
EMBED_MODEL = "nomic-embed-text"
ACCESS_LEVELS = ["public", "confidential"]


def chunk_text(text, max_chars=800):
    """Split a document into chunks of up to max_chars, keeping paragraphs whole.

    Smaller chunks make search more precise: the chatbot gets the one
    relevant section instead of a whole document.
    """
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks, current = [], ""
    for para in paragraphs:
        if current and len(current) + len(para) + 2 > max_chars:
            chunks.append(current)
            current = ""
        current = f"{current}\n\n{para}" if current else para
        # A single paragraph longer than max_chars gets hard-split
        while len(current) > max_chars:
            chunks.append(current[:max_chars])
            current = current[max_chars:]
    if current:
        chunks.append(current)
    return chunks


def embed(text):
    """Turn text into a vector (a list of numbers that captures its meaning)."""
    return ollama.embed(model=EMBED_MODEL, input=text)["embeddings"][0]


def main():
    client = chromadb.PersistentClient(path=str(DB_DIR))

    # Start fresh each run, so re-running doesn't create duplicates
    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass
    collection = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

    total = 0
    for level in ACCESS_LEVELS:
        for path in sorted((DATA_DIR / level).glob("*.md")):
            chunks = chunk_text(path.read_text(encoding="utf-8"))
            collection.add(
                ids=[f"{level}/{path.name}#{i}" for i in range(len(chunks))],
                documents=chunks,
                # nomic-embed-text works best with this prefix on documents
                embeddings=[embed("search_document: " + c) for c in chunks],
                metadatas=[{"source": path.name, "access": level} for _ in chunks],
            )
            total += len(chunks)
            print(f"  [{level:12}] {path.name}: {len(chunks)} chunks")

    print(f"\nDone. Stored {total} chunks in {DB_DIR.name}/")


if __name__ == "__main__":
    main()
