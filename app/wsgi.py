"""Gunicorn entry point."""

from doom import create_app

app = create_app()
