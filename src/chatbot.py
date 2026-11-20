"""Answer questions using retrieved documents (RAG) and a local LLM.

RAG = Retrieve relevant chunks -> Augment the prompt with them -> Generate an answer.
Each user has a role, and retrieval only returns documents that role may read.
Prompt-injection guardrails (src/guardrails.py) wrap every step.

Run from the project root:
    python -m src.chatbot                  # with guardrails
    python -m src.chatbot --no-guardrails  # without, to demonstrate the attacks
"""
import sys

import ollama

from src import guardrails
from src.auth import USERS, get_role
from src.retriever import retrieve

CHAT_MODEL = "llama3.2"

# The original, unprotected prompt from Milestone 3, kept to demo the attacks
UNSAFE_SYSTEM_PROMPT = """You are a cybersecurity knowledge assistant.
Answer the user's question using only the information in the provided context.
If the context does not contain the answer, say that you don't know.
Keep answers concise and mention which source document you used."""


def _ask_llm(messages):
    response = ollama.chat(model=CHAT_MODEL, messages=messages, options={"temperature": 0.1})
    return response["message"]["content"]


def answer_unsafe(question, role, k=3):
    """No guardrails: retrieved text goes straight into the prompt."""
    chunks = retrieve(question, role, k=k)
    context = "\n\n".join(f"[Source: {c['source']}]\n{c['text']}" for c in chunks)
    reply = _ask_llm([
        {"role": "system", "content": UNSAFE_SYSTEM_PROMPT},
        {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
    ])
    return reply, chunks


def answer(question, role, k=3):
    """Full pipeline with all four guardrail layers."""
    # Layer 1: direct injection in the question
    attack = guardrails.check_input(question)
    if attack:
        guardrails.log_event(f"input_blocked:{attack}", question, role)
        return guardrails.REFUSAL, []

    # Retrieval (role-based access control happens inside retrieve)
    chunks = retrieve(question, role, k=k)

    # Layer 2: indirect injection hidden in documents
    chunks, quarantined = guardrails.screen_chunks(chunks)
    for q in quarantined:
        guardrails.log_event(f"chunk_quarantined:{q['reason']}", f"{q['source']}: {q['text']}", role)

    # Layer 3: hardened prompt with a fresh canary each time
    canary = guardrails.new_canary()
    reply = _ask_llm(guardrails.build_messages(question, chunks, canary))

    # Layer 4: check the answer before showing it
    problem = guardrails.check_output(reply, chunks, canary)
    if problem:
        guardrails.log_event(f"output_blocked:{problem}", reply, role)
        return guardrails.REFUSAL, chunks

    return reply, chunks


def main():
    safe_mode = "--no-guardrails" not in sys.argv
    ask = answer if safe_mode else answer_unsafe

    print("Secure RAG Chatbot. Type 'quit' to exit.")
    print("Guardrails: " + ("ON" if safe_mode else "OFF (demo mode, unsafe!)"))
    print("Demo users: " + ", ".join(f"{u} ({r})" for u, r in USERS.items()) + "\n")
    try:
        username = input("Username: ")
        role = get_role(username)
    except PermissionError as e:
        print(f"Access denied. {e}")
        return
    except (EOFError, KeyboardInterrupt):
        return
    print(f"Logged in as {username.strip().lower()} ({role})\n")

    while True:
        try:
            question = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if question.lower() in {"quit", "exit"}:
            break
        if not question:
            continue

        reply, chunks = ask(question, role)
        print(f"\nBot: {reply}")
        if chunks:
            sources = sorted({f"{c['source']} [{c['access']}]" for c in chunks})
            print(f"Sources: {', '.join(sources)}")
        print()
    print("Bye!")


if __name__ == "__main__":
    main()
