"""Test setup: these tests cover pure functions only and must never touch the network."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# common.py builds the Groq client at import and needs a key to exist. No call is made.
os.environ.setdefault("GROQ_API_KEY", "test-key-not-real")

import requests  # noqa: E402

import privacy  # noqa: E402


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("test tried to use the network")
    monkeypatch.setattr(requests, "get", blocked)
    monkeypatch.setattr(requests, "post", blocked)


@pytest.fixture(autouse=True)
def aliases(monkeypatch):
    """An empty alias table marked as loaded, so nothing asks the indexer for agents."""
    table = {}
    monkeypatch.setattr(privacy, "_aliases", table)
    monkeypatch.setattr(privacy, "_aliases_loaded", True)
    return table
