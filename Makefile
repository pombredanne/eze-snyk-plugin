##############################################
# Make File Spec
# https://www.gnu.org/software/make/
# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html
##############################################

.PHONY: install lint

##############################################
# DEVELOPER COMMANDS
##############################################

# install local eze package and other packages to start programming your plugin for Eze
install:
	python -m pip install -r requirements-dev.txt

# to check formatting of your code
lint:
	black src
	
test:
	python -m pytest tests -vv --cov=src --cov-branch --cov-report=term-missing --cov-report html:reports/coverage/cov_html --cov-report=xml:reports/coverage/coverage.xml --junitxml=reports/xunit/test-results.xml -o junit_family=xunit1 || true

test-snapshot-update:
	python -m pytest tests --snapshot-update

##############################################
# PLUGIN PACKAGE COMMANDS
##############################################

# build package for this plugin
plugin-build:
	rm -f dist/*.tar.gz
	python setup.py sdist
	rm -f scripts/*.tar.gz
	mkdir -p scripts/
	cp dist/*.tar.gz scripts/

plugin-install: plugin-build
	pip install scripts/eze-snyk-plugin-*.tar.gz

# release to test pip
release-pypi-test: plugin-build
	twine upload --repository testpypi dist/*

# release to test pip
release-pypi: plugin-build
	twine upload dist/*

# release to test pip
release-test: plugin-build
	twine upload --repository testpypi dist/*

##############################################
# BUILD SYSTEM COMMANDS
##############################################

##############################################
# MISC COMMANDS
##############################################

# for dependency analysis
dump-local-pip-versions:
	pip freeze > reports/pip-current-requirements.txt

# Run to fix black if it breaks its self locally
# tip from https://stackoverflow.com/questions/59343656/problem-with-using-black-code-formatter-cant-import-ast3
repair-black:
	pip install --force-reinstall --upgrade typed-ast black

# Run to fix pip packages
# common if you accidentally have two pythons installed and the two pip repos get muddled
# with the local pip registry being incorrect
repair-pip:
	python -m pip install ––upgrade --force-reinstall pip
	pip install --upgrade --force-reinstall -r requirements-dev.txt  -r requirements.txt

# Run to fix pyenv not linking to recently installed pip packages
repair-pyenv:
	pyenv rehash


all: install lint

.DEFAULT_GOAL := all
