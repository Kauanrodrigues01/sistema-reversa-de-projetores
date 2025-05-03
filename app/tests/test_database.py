from app.database import get_session


def test_get_session_basic():
    """Basic test that get_session yields without errors"""
    gen = get_session()
    try:
        session = next(gen)
        assert session is not None
    finally:
        try:
            next(gen)
        except StopIteration:
            pass
