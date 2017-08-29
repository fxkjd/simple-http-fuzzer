# Simplefuzzer - A simple HTTP python fuzzer

This is a python HTTP fuzzer implementation. 

Simplefuzzer input is a HTTP template (raw request) and a dictionary.
The HTTP parameters that need to be fuzzed are marked with `{{}}`
It sends HTTP requests for each input defined in the 
raw HTTP and for each input in the dictionary.

The output is a folder structure containing each request and its respective response.
It Also logs an execution summary.

## Install

Simple clone this repository.

Dependencies:

- argparse
- requests
- hashlib
- BaseHTTPServer
- StringIO

## Usage

To get a list of basic options use:

    $ simplefuzzer.py -h

To launch the fuzzer, simply run:

    $ simplefuzzer.py fuzzer -t HTTP_TEMPLATE -d DICTIONARY

This will create an `output` folder containing each request and its respective response.

Simplefuzzer also allows to send a HTTP raw request:

    $ simplefuzzer.py request -r HTTP_RAW_REQUEST

## Example

The following HTTP request is an example of a template:

    POST /checkIP HTTP/1.1
    Host: yourhostname
    Keep-Alive: timeout=15
    Connection: Keep-Alive
    Content-Length: 593

    <?xml version=1.0 encoding=UTF-8?>
    <request>
       <sc_xml_ver>1.0</sc_xml_ver>
       <ipAddress>{{127.0.0.1}}</ipAddress>
       <port>{{80}}</port>
    </request>

The value between `{{` and `}}` will be the one used when this parameter is not being fuzzed.
If there is no value, a default one will be used instead.

You can fuzz it by running:

    $ simplefuzzer.py fuzzer -t HTTP_TEMPLATE -d DICTIONARY

This will fuzz the `<ipAddress>` parameter with each entry of the dictionary,
and it will create the following folder structure:

    output
    └── getagentinfowb_pre.txt
        ├── req - HTTP requests
        │   ├── param0_dictionaryValue0_md5requesthash
        │   ├── ... 
        │   └── param0_dictionaryValueN_md5requesthash
        ├── res - HTTP responses
        │   ├── param0_dictionaryValue0_md5requesthash
        │   ├── ...
        │   └── paramN_dictionaryValueN_md5requesthash
        └── results.log - Summary

Additionally you can pass a folder as `DICTIONARY` value. This will fuzz `<ipAddress>` parameter 
with each dictionary of the `DICTIONARY` folder.
The resulting folder structure will be the following:

    output
    └── getagentinfowb_pre.txt
        ├── req - HTTP requests
        │   ├── dictionary_0 
        │   │   ├── param0_dictionaryValue0_md5requesthash
        │   │   ├── ... 
        │   │   └── paramN_dictionaryValueN_md5requesthash
        │   ├── ...
        │   └── dictionary_N
        │       ├── param0_dictionaryValue0_md5requesthash
        │       ├── ... 
        │       └── paramN_dictionaryValueN_md5requesthash
        ├── res
        │   ├── dictionary_0 
        │   │   ├── param0_dictionaryValue0_md5requesthash
        │   │   ├── ... 
        │   │   └── paramN_dictionaryValueN_md5requesthash
        │   ├── ...
        │   └── dictionary_N
        │       ├── param0_dictionaryValue0_md5requesthash
        │       ├── ... 
        │       └── paramN_dictionaryValueN_md5requesthash
        └── results.log

## License

  [LGPL3](LICENSE)
