"""Fixture fleet — authlib.tokens: the vulnerable sink lives here."""
import pickle


def load_session(blob):
    """Deserialize a session blob — CRITICAL sink in the shared library."""
    return pickle.loads(blob)


def sign_token(payload):
    return {"sig": sum(ord(c) for c in payload), "payload": payload}
