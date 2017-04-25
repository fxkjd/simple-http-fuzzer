# Simplefuzzer - A simple HTTP python fuzzer

This is a python HTTP fuzzer implementation. 

Simplefuzz input is a HTTP template (raw request) and a dictionary.
The HTTP parameters that need to be fuzzed are marked with `{}`
It sends HTTP requests for each input defined in the 
raw HTTP and for each input in the dictionary.

The output is a folder structure containing each request and its respective response.
It Also logs an execution summary.

## Install

Simple clone this repository.

## Usage

To get a list of basic options use:

    $ simplefuzzer.py -h

To launch it, simply run:

    $ simplefuzzer.py -t HTTP_TEMPLATE -d DICTIONARY

This will create an `output` folder containing each request and its respective response.

## Example

The following HTTP request is an example of template:

    POST /checkIP HTTP/1.1
    Host: yourhostname
    Keep-Alive: timeout=15
    Connection: Keep-Alive
    Content-Length: 593

    <?xml version=1.0 encoding=UTF-8?>
    <request>
       <sc_xml_ver>1.0</sc_xml_ver>
       <ipAddress>{}</ipAddress>
    </request>

You can fuzz it by running:

    $ simplefuzzer.py -t HTTP_TEMPLATE -d DICTIONARY

This will create the following folder structure:

    output
    ├── req - HTTP requests
    │   ├── param0_dictionaryValue0_md5requesthash
    │   ├── ... 
    │   └── param0_dictionaryValueN_md5requesthash
    ├── res - HTTP responses
    │   ├── param0_dictionaryValue0_md5requesthash
    │   ├── ...
    │   └── param0_dictionaryValue0_md5requesthash
    └── results.log - Summary

