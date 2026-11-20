"""Role-based access control tests.

Run from the project root (Ollama running, database built with python -m src.ingest):
    python -m pytest -v
"""
import pytest

from src.auth import allowed_access_levels, get_role
from src.retriever import retrieve

CONFIDENTIAL_QUESTIONS = [
    "What are the open high severity pentest findings?",
    "What should we do first in a SEV-1 incident?",
    "What is the name of the forensics evidence bucket?",
]


@pytest.mark.parametrize("question", CONFIDENTIAL_QUESTIONS)
def test_intern_never_retrieves_confidential(question):
    chunks = retrieve(question, role="intern", k=5)
    assert chunks, "expected some public results"
    assert all(c["access"] == "public" for c in chunks)


def test_security_team_can_retrieve_confidential():
    chunks = retrieve("What are the open high severity pentest findings?", role="security_team")
    assert any(c["access"] == "confidential" for c in chunks)


def test_unknown_role_is_denied():
    with pytest.raises(PermissionError):
        retrieve("anything", role="admin")


def test_unknown_user_is_denied():
    with pytest.raises(PermissionError):
        get_role("mallory")


def test_policy_cannot_be_modified_by_caller():
    allowed_access_levels("intern").append("confidential")
    assert allowed_access_levels("intern") == ["public"]
