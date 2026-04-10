"""Launch helpers for running the Streamlit app from python app.py."""

import os
import subprocess
import sys


BOOTSTRAP_ENV = "CYPHERQUBE_STREAMLIT_BOOTSTRAPPED"


def relaunch_with_streamlit(script_path: str) -> int:
    env = os.environ.copy()
    env[BOOTSTRAP_ENV] = "1"
    return subprocess.call([sys.executable, "-m", "streamlit", "run", script_path], env=env)
