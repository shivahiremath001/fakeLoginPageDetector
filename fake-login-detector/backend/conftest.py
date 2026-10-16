"""
conftest.py — pytest configuration: adds the backend root to sys.path so
that `from app.xxx import ...` works without installing the package.
"""
import sys
from pathlib import Path

# Add the backend directory (parent of this file) to the module search path
sys.path.insert(0, str(Path(__file__).parent))
