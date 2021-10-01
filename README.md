
# Introduction 

Snyk plugin implemented to run in Eze.

# Build and Test

## Install Eze and all required tools Locally (via make)

```bash
make install
```

## Develop your plugin for Eze

### Run Unit Tests

```bash
make test
```

### Run Unit Tests: How to update pytest snapshot tests

Run this command to regenerate the fixtures after changes.

```bash
make test-snapshot-update
```

_ps. remember to always manually check the diff before committing updated snapshots!_

Of course it's your plugin so if you don't like snapshot testing (it is controversial) you don't need to include them!

### Snapshot fixture location

All files will be stored in here

```
tests/snapshots
```

## Generate your tar plugin package

After you completed your plugin and it's ready to be used on Eze. You will have to generate a tar (package) file, run:

```bash
plugin-build
```


## Install Plugin Locally (Manual via pip)
After the *.tar file is generated, open the bash terminal on **Eze-cli** project and enter:

```python
pip install dist/eze-snyk-plugin-*.tar.gz # [tar_location]
```

### Test installed correctly
On Eze-CLI project run: 

```bash
eze tools list
eze reporters list
```
Your plugin package should be listed as a tool. Also if applies, your reporters should be displayed.

## References
This plugin used Snyk tool, to read more [access this link](https://snyk.io/)