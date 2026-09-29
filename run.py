"""
run.py — Development entrypoint.

In production, the app is served by gunicorn (see gunicorn.conf.py).
This file is ONLY for local development via `python run.py`.

debug=True is driven by the config class, NOT hardcoded (fixes H-7).
"""
from __future__ import annotations

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    # debug is controlled by DevelopmentConfig.DEBUG — never hardcoded
    app.run(host="0.0.0.0", port=port)