"""Timestamp helpers."""
import datetime


def ts() -> str:
    """Return current datetime as formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
