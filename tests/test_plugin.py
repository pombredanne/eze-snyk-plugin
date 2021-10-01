from src import plugin
from src.snyk import SnykTool


class TestPlugin:
    def test_get_reporters(self):
        """Test that the reporters are listed"""
        reporters_snapshot = {}
        assert plugin.get_reporters() == reporters_snapshot

    def test_get_tools(self):
        """Test that the tools are listed"""
        tools_snapshot = {"snyk": SnykTool}
        assert plugin.get_tools() == tools_snapshot
