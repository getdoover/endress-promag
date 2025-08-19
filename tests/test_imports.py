"""
Basic tests for an application.

This ensures all modules are importable and that the config is valid.
"""

def test_import_app():
    from endress_promag.application import EndressPromagApplication
    assert EndressPromagApplication

def test_config():
    from endress_promag.app_config import EndressPromagConfig

    config = EndressPromagConfig()
    assert isinstance(config.to_dict(), dict)

def test_ui():
    from endress_promag.app_ui import EndressPromagUI
    assert EndressPromagUI

def test_state():
    from endress_promag.app_state import EndressPromagState
    assert EndressPromagState