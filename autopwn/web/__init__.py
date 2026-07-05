# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Autopwn web console — a Bootstrap SPA served by uvicorn over the existing
engine (store / jobs / report). All assets are vendored so it runs offline."""
from .server import create_app, run  # noqa: F401
