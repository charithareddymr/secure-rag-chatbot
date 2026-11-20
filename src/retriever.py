"""Search the vector database, returning only chunks the user's role may see.

Access control is enforced HERE, in the retrieval layer, not in the LLM prompt.
A prompt can be talked out of its rules; a database filter cannot. Confidential
chunks never reach the model for a user who isn't allowed to see them.

Try it from the project root:
    python -m src.retriever intern "What are the open high severity pentest findings?"
"""
import sys

import chromadb
import ollama

from src.auth import allowed_access_levels
from src.ingest import COLLECTION, DB_DIR, EMBED_MODEL


def get_collection():
    client = chromadb.PersistentClient(path=str(DB_DIR))
    return client.get_collection(COLLECTION)


def retrieve(query, role, k=3):
    """Return the k most relevant chunks that this role is allowed to read."""
    allowed = allowed_access_levels(role)  # raises PermissionError for unknown roles

    # nomic-embed-text works best with this prefix on questions
    query_vector = ollama.embed(model=EMBED_MODEL, input="search_query: " + query)["embeddings"][0]
    results = get_collection().query(
        query_embeddings=[query_vector],
        n_results=k,
        where={"access": {"$in": allowed}},  # the access-control filter
    )
    return [
        {"text": doc, "source": meta["source"], "access": meta["access"], "score": 1 - dist}
        for doc, meta, dist in zip(
            results["documents"][0], results["metadatas"][0], results["distances"][0]
        )
    ]


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('Usage: python -m src.retriever <role> "<question>"')
        sys.exit(1)
    role, question = sys.argv[1], " ".join(sys.argv[2:])
    print(f"Role: {role}\nQuestion: {question}")
    for r in retrieve(question, role):
        print(f"\n--- {r['source']} [{r['access']}]  similarity={r['score']:.2f}")
        print(r["text"][:300] + ("..." if len(r["text"]) > 300 else ""))
