import os
import sys

# Ensure the tests directory is on sys.path so port_helpers is importable
# when test files are run directly or via python -m unittest discover.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
