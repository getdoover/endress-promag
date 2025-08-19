from pydoover.docker import run_app

from .application import EndressPromagApplication
from .app_config import EndressPromagConfig

def main():
    """
    Run the application.
    """
    run_app(EndressPromagApplication(config=EndressPromagConfig()))
