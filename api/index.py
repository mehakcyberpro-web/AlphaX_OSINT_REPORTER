import sys
from pathlib import Path

# Make the repository's backend package importable in Vercel's Python runtime.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.main import app

# Vercel's Python runtime detects the ASGI app exported as `app`.
