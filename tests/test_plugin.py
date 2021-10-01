from src import plugin
from src.snyk import SnykTool, SnykContainerTool, SnykIacTool


class TestPlugin:
    def test_get_reporters(self):
        """Tests that the reporters are listed"""
        reporters_snapshot = {}
        assert plugin.get_reporters() == reporters_snapshot

    def test_get_tools(self):
        """Tests that the tools are listed"""
        tools_snapshot = {
            "snyk": SnykTool,
            "snyk-container": SnykContainerTool,
            "snyk-iac": SnykIacTool,
        }
        assert plugin.get_tools() == tools_snapshot
