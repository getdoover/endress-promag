from pydoover.docker import run_app

from .application import EndressPromagApplication


def main():
    """
    Run the application.
    """
    run_app(EndressPromagApplication())
