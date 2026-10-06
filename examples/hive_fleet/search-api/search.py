"""Fixture fleet — search-api: clean repository; the fleet sweep must stay silent."""
import hashlib


def index_query(term):
    return hashlib.sha256(term.encode()).hexdigest()
