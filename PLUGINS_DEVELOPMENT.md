# Overview
This is a how-to manual to guide anyone to implement a plugin class from Scratch. Also, how to use the plugin in Eze.


# Implementation

## Review plugin documentation
Read all the documentation about the plugin you want to include in the project. Useful info:

- Command/Actions to install plugin.
- Command to execute the plugin
- Useful arguments/flags to pass into the executable command.
- Structure of the response, type, info.
- Plugin's version

>**Note:** Make sure the plugin you choose is kept mantained, so the libraries are supported.

## Include plugin files

### I. Install the plugin
The installation may vary based on the plugin: 
 * If binary file: download it and save it on your home directory
 * If python package: install it by using "pip install ..."
 * If Node library: by using "npm install ..."
 * Other ways are via apt-get or docker.

>Step is finished when you are able to run the plugin locally. 
```[plugin] --version``` *Although this is not an unique command*.

### Install the plugin on your Python environment

1. After the *.tar file is generated, open the bash terminal on **Eze-cli** project and enter:

```bash
pip install [tar_location]
```

2. Finally, you can check the list of the tools/reporters and verify the new plugin is listed:
```bash
eze tools list  
eze reporters list  
```
