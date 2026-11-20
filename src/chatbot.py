"""Answer questions using retrieved documents (RAG) and a local LLM.

RAG = Retrieve relevant chunks -> Augment the prompt with them -> Generate an answer.

Run from the project root:
    python -m src.chatbot
"""
import ollama

from src.retriever import retrieve

CHAT_MODEL = "llama3.2"

SYSTEM_PROMPT = """You are a cybersecurity knowledge assistant.
Answer the user's question using only the information in the provided context.
If the context does not contain the answer, say that you don't know.
Keep answers concise and mention which source document you used."""


def build_context(chunks):
    """Join the retrieved chunks into one block of text, labelled by source."""
    return "\n\n".join(f"[Source: {c['source']}]\n{c['text']}" for c in chunks)


def answer(question, k=3):
    """Retrieve relevant chunks, then ask the LLM to answer using them."""
    chunks = retrieve(question, k=k)
    response = ollama.chat(
        model=CHAT_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Context:\n{build_context(chunks)}\n\nQuestion: {question}"},
        ],
        options={"temperature": 0.1},  # low = more focused, less creative answers
    )
    return response["message"]["content"], chunks


def main():
    print("Secure RAG Chatbot. Type 'quit' to exit.\n")
    while True:
        try:
            question = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if question.lower() in {"quit", "exit"}:
            break
        if not question:
            continue

        reply, chunks = answer(question)
        sources = sorted({f"{c['source']} [{c['access']}]" for c in chunks})
        print(f"\nBot: {reply}")
        print(f"Sources: {', '.join(sources)}\n")
    print("Bye!")


if __name__ == "__main__":
    main()
