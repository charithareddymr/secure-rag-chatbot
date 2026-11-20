"""Search the vector database for the chunks most relevant to a question.

Try it from the project root:
    python -m src.retriever "How do I prevent SQL injection?"
"""
import sys

import chromadb
import ollama

from src.ingest import COLLECTION, DB_DIR, EMBED_MODEL


def get_collection():
    client = chromadb.PersistentClient(path=str(DB_DIR))
    return client.get_collection(COLLECTION)


def retrieve(query, k=3):
    """Return the k chunks whose meaning is closest to the query."""
    # nomic-embed-text works best with this prefix on questions
    query_vector = ollama.embed(model=EMBED_MODEL, input="search_query: " + query)["embeddings"][0]
    results = get_collection().query(query_embeddings=[query_vector], n_results=k)
    return [
        {"text": doc, "source": meta["source"], "access": meta["access"], "score": 1 - dist}
        for doc, meta, dist in zip(
            results["documents"][0], results["metadatas"][0], results["distances"][0]
        )
    ]


if __name__ == "__main__":
    question = " ".join(sys.argv[1:]) or "How do I prevent SQL injection?"
    print(f"Question: {question}")
    for r in retrieve(question):
        print(f"\n--- {r['source']} [{r['access']}]  similarity={r['score']:.2f}")
        print(r["text"][:300] + ("..." if len(r["text"]) > 300 else ""))
