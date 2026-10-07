import os
import sys

# Vercel executes this file from the api/ function directory in some
# runtimes. Explicitly add the repository root so web_app.py and
# connections.py are always importable.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from web_app import app

__all__ = ["app"]
