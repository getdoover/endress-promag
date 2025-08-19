from pydoover.docker import run_app

from .application import SampleApplication
from .app_config import SampleConfig

def main():
    """
    Run the application.
    """
    run_app(SampleApplication(config=SampleConfig()))
