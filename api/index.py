"""
Vercel Serverless Function Entrypoint for SentinelAI.
@vercel/python detects and routes ASGI/FastAPI requests to `app`.
"""
import os
import sys
from pathlib import Path

# Ensure the root workspace path is registered in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Inform components that we are running inside Vercel serverless environment
os.environ["VERCEL"] = "1"

from SentinelAI.api.server import app

# Export app for Vercel ASGI serverless handler
__all__ = ["app"]
