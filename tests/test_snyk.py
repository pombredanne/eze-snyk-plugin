# pylint: disable=missing-module-docstring,missing-class-docstring
from unittest import mock
import shlex
import json
from src.snyk import SnykTool, SnykContainerTool, SnykIacTool
from eze.core.tool import ToolMeta

from eze.utils.io import create_tempfile_path, load_json
from eze.utils.cli import build_cli_command


class ToolMetaTestBase:
    ToolMetaClass = ToolMeta

    def assert_parse_report_snapshot_test(
        self,
        snapshot,
        input_config: dict = None,
        input_fixture_location: str = None,
        output_fixture_location: str = None,
    ):
        """Help function to take a input fixture, and test output matches given snapshot

        Default Input Fixture:
            tests/__fixtures__/raw-XXX-report.json

        Default Output Snapshot:
            tests/snapshots/XXX-result-output.json"""
        # Given
        if not input_config:
            input_config = {}
        if not input_fixture_location:
            input_fixture_location = (
                f"tests/__fixtures__/raw-{self.SNAPSHOT_PREFIX}-report.json"
            )
        if not output_fixture_location:
            output_fixture_location = f"{self.SNAPSHOT_PREFIX}-result-output.json"

        input_report = load_json(str(input_fixture_location))
        testee = self.ToolMetaClass.parse_report(self.ToolMetaClass, input_report)
        # When
        # output = testee.parse_report(input_report)
        output_snapshot = json.dumps(testee, default=vars, indent=2, sort_keys=True)
        # Then
        # WARNING: this is a snapshot test, any changes to format will edit this and the snapshot will need to be updated
        snapshot.assert_match(output_snapshot, output_fixture_location)


class TestSnykTool(ToolMetaTestBase):
    ToolMetaClass = SnykTool
    SNAPSHOT_PREFIX = "snyk"

    def test_creation__no_config(self):
        # Given
        expected_config = {
            "PACKAGE_FILE": None,
            "PACKAGE_MANAGER": None,
            "REPORT_FILE": create_tempfile_path("tmp-snyk-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykTool()
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "PACKAGE_FILE": "somewhere/package.json",
            "PACKAGE_MANAGER": "npm",
        }
        expected_config = {
            "PACKAGE_FILE": "somewhere/package.json",
            "PACKAGE_MANAGER": "npm",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykTool(input_config)
        # Then
        assert testee.config == expected_config

    @mock.patch(
        "src.snyk.extract_cmd_version",
        mock.MagicMock(return_value="1.531.0"),
    )
    def test_check_installed__success(self):
        # When
        SnykTool._version_cache = None
        expected_output = "1.531.0"
        output = SnykTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch(
        "src.snyk.extract_cmd_version",
        mock.MagicMock(return_value="NOT TO BE CALLED"),
    )
    def test_check_installed__success_with_cache(self):
        # When
        SnykTool._version_cache = "1.531.Cache-Version"
        expected_output = "1.531.Cache-Version"
        output = SnykTool.check_installed()
        # Then
        assert output == expected_output

    @mock.patch("src.snyk.extract_cmd_version", mock.MagicMock(return_value=False))
    def test_check_installed__failure_unavailable(self):
        # When
        SnykTool._version_cache = None
        expected_output = False
        output = SnykTool.check_installed()
        # Then
        assert output == expected_output

    def test_parse_report__node_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "tests/__fixtures__/raw-snyk-node-report.json",
            "snyk-node-output.json",
        )

    def test_parse_report__python_snapshot(self, snapshot):
        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(
            snapshot,
            {},
            "tests/__fixtures__/raw-snyk-python-report.json",
            "snyk-python-output.json",
        )

    def test_help_text_fields(self, snapshot):
        output = f"""short_description:
======================
proprietary multi language SCA scanner

config_help:
======================
[snyk]
# PACKAGE_FILE str [OPTIONAL]
# Optional run synk with --file argument
# for specifying explicit or nested package file
# aka a package.json, pom.xml, or requirements.txt
# 
PACKAGE_FILE = "..."


# PACKAGE_MANAGER str [OPTIONAL]
# Optional run synk with --package-manager argument
# for specifying type of package file, only needed if non-stndard name
# aka pip
# 
PACKAGE_MANAGER = "..."


# REPORT_FILE str [OPTIONAL]
# output report location (will default to tmp file otherwise)
# default value: 
#   REPORT_FILE = "<tempdir>/.eze-temp/tmp-snyk-report.json"
# 
REPORT_FILE = "..."



# Common Tool Config

# ADDITIONAL_ARGUMENTS str [OPTIONAL]
# common field that can be used to postfix arbitrary arguments onto any plugin cli tooling
# 
ADDITIONAL_ARGUMENTS = "..."


# IGNORE_BELOW_SEVERITY str [OPTIONAL]
# vulnerabilities severities to ignore, by CVE severity level
# aka if set to medium, would ignore medium/low/none/na
# available levels: critical, high, medium, low, none, na
# 
IGNORE_BELOW_SEVERITY = "..."


# IGNORED_VULNERABILITIES list [OPTIONAL]
# vulnerabilities to ignore, by CVE code or by name
# feature only for use when vulnerability mitigated or on track to be fixed
# 
IGNORED_VULNERABILITIES = ["..."]


# IGNORED_FILES list [OPTIONAL]
# vulnerabilities in files or prefix folders to ignore
# feature only for use when vulnerability mitigated or on track to be fixed
# 
IGNORED_FILES = ["..."]


# DEFAULT_SEVERITY str [OPTIONAL]
# Severity to set vulnerabilities, when tool doesn't provide a severity, defaults to na
# available levels: critical, high, medium, low, none, na
# 
DEFAULT_SEVERITY = "..."


# EXCLUDE list [OPTIONAL]
# files or prefix folders to exclude in the scanning process
# 
EXCLUDE = ["..."]




install_help:
======================
In most cases all that is required to install snyk is node and npm install
npm install snyk -g
snyk --version

Then ensure your snyk instance is configured
snyk auth

more_info:
======================
https://support.snyk.io/hc/en-us
https://docs.npmjs.com/downloading-and-installing-node-js-and-npm

note a root level .snyk should be created to configure synk
see https://support.snyk.io/hc/en-us/articles/360007487097-The-snyk-file
"""
        snapshot.assert_match(output, f"snyk-help_text.txt")


class TestSnykContainerTool(ToolMetaTestBase):
    ToolMetaClass = SnykContainerTool
    SNAPSHOT_PREFIX = "snyk-container"

    def test_creation__no_config(self):
        # Given
        input_config = {"DOCKER_TAG": "debian"}
        expected_config = {
            "DOCKERFILE": None,
            "PLATFORM": None,
            "DOCKER_TAG": "debian",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-container-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykContainerTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "DOCKER_TAG": "debian:stable",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "DOCKERFILE": "some-dockerfile/dockerfile",
            "PLATFORM": "linux",
        }
        expected_config = {
            "DOCKER_TAG": "debian:stable",
            "DOCKERFILE": "some-dockerfile/dockerfile",
            "PLATFORM": "linux",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-container-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykContainerTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_parse_report__snapshot(self, snapshot):
        # Given
        input_config = {"DOCKER_TAG": "debian"}

        # Test container fixture and snapshot
        self.assert_parse_report_snapshot_test(snapshot, input_config)

    def test_build_command__snyk_std(self):
        expected_output = "snyk container test debian:stable --file=some-dockerfile/dockerfile --platform=linux --something foo"
        input_cli_config = {
            "BASE_COMMAND": shlex.split("snyk container test"),
            "ARGUMENTS": ["REPOSITORY"],
            "FLAGS": {
                "DOCKERFILE": "--file=",
                "PLATFORM": "--platform=",
                "TEMP_REPORT_FILE": "--json-file-output=",
            },
        }
        input_config = {
            "REPOSITORY": "debian:stable",
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "DOCKERFILE": "some-dockerfile/dockerfile",
            "PLATFORM": "linux",
        }

        output = shlex.join(build_cli_command(input_cli_config, input_config))

        assert output == expected_output

    def test_help_text_fields(self, snapshot):
        output = f"""short_description:
======================
proprietary container scanner

config_help:
======================
[snyk-container]
# DOCKER_TAG str
# Required image repository to scan
# Optional image repository can include tag to scan
# 
# For detailed IMAGE details
# See https://support.snyk.io/hc/en-us/articles/360003946917-Test-images-with-the-Snyk-Container-CLI
# 
# 
DOCKER_TAG = "debian:stable"

# DOCKERFILE str [OPTIONAL]
# Optional docker file
# maps to --file snyk argument
# 
DOCKERFILE = "..."
"""
        snapshot.assert_match(output, f"snyk-container-help_text.txt")


class TestSnykIacTool(ToolMetaTestBase):
    ToolMetaClass = SnykIacTool
    SNAPSHOT_PREFIX = "snyk-iac"

    def test_creation__no_config(self):
        # Given
        input_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
        }
        expected_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-iac-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykIacTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_creation__with_config(self):
        # Given
        input_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
            "ADDITIONAL_ARGUMENTS": "--something foo",
        }
        expected_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
            "REPORT_FILE": create_tempfile_path("tmp-snyk-iac-report.json"),
            #
            "ADDITIONAL_ARGUMENTS": "--something foo",
            "IGNORED_FILES": None,
            "EXCLUDE": [],
            "IGNORED_VULNERABILITIES": None,
            "IGNORE_BELOW_SEVERITY": None,
            "DEFAULT_SEVERITY": None,
        }
        # When
        testee = SnykIacTool(input_config)
        # Then
        assert testee.config == expected_config

    def test_parse_report__snapshot(self, snapshot):
        # Given
        input_config = {
            "SOURCE": "goat-owasp-kubernettes/batch-check",
        }

        self.assert_parse_report_snapshot_test(snapshot, input_config)

    def test_help_text_fields(self, snapshot):
        output = f"""short_description:
======================
proprietary infrastructure scanner

config_help:
======================
[snyk-iac]
# SOURCE str
# Required iac setup to scan
# 
# For detailed details
# See https://support.snyk.io/hc/en-us/articles/360012429477-Test-your-Kubernetes-files-with-our-CLI-tool
# 
# 
SOURCE = "..."


# REPORT_FILE str [OPTIONAL]
# output report location (will default to tmp file otherwise)
# default value: 
#   REPORT_FILE = "<tempdir>/tmp-snyk-iac-report.json"
# 
REPORT_FILE = "..."



# Common Tool Config

# ADDITIONAL_ARGUMENTS str [OPTIONAL]
# common field that can be used to postfix arbitrary arguments onto any plugin cli tooling
# 
ADDITIONAL_ARGUMENTS = "..."


# IGNORE_BELOW_SEVERITY str [OPTIONAL]
# vulnerabilities severities to ignore, by CVE severity level
# aka if set to medium, would ignore medium/low/none/na
# available levels: critical, high, medium, low, none, na
# 
IGNORE_BELOW_SEVERITY = "..."


# IGNORED_VULNERABILITIES list [OPTIONAL]
# vulnerabilities to ignore, by CVE code or by name
# feature only for use when vulnerability mitigated or on track to be fixed
# 
IGNORED_VULNERABILITIES = ["..."]


# IGNORED_FILES list [OPTIONAL]
# vulnerabilities in files or prefix folders to ignore
# feature only for use when vulnerability mitigated or on track to be fixed
# 
IGNORED_FILES = ["..."]


# DEFAULT_SEVERITY str [OPTIONAL]
# Severity to set vulnerabilities, when tool doesn't provide a severity, defaults to na
# available levels: critical, high, medium, low, none, na
# 
DEFAULT_SEVERITY = "..."


# EXCLUDE list [OPTIONAL]
# files or prefix folders to exclude in the scanning process
# 
EXCLUDE = ["..."]




install_help:
======================
In most cases all that is required to install snyk is node and npm install
npm install snyk -g
snyk --version

Then ensure your snyk instance is configured
snyk auth

more_info:
======================
https://support.snyk.io/hc/en-us
https://docs.npmjs.com/downloading-and-installing-node-js-and-npm

note a root level .snyk should be created to configure synk
see https://support.snyk.io/hc/en-us/articles/360007487097-The-snyk-file
"""
        snapshot.assert_match(output, f"snyk-iac-help_text.txt")
