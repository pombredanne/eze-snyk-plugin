"""Lists out the inbuilt plugins in Project"""
from src.snyk import SnykTool, SnykContainerTool, SnykIacTool


def get_reporters() -> dict:
    """Return the reporters in plugin"""
    return {}


def get_tools() -> dict:
    """Return the tools in plugin"""
    return {
        "snyk": SnykTool,
        "snyk-container": SnykContainerTool,
        "snyk-iac": SnykIacTool,
    }
