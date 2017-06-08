#!/usr/bin/env python

import argparse, os, requests, sys, hashlib
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

#class for parsing HTTP raw request
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        self.body = ""
        for line in self.rfile:
            self.body = self.body + line 

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def response_to_string(response):
    string = ""
    #HTTP 
    try:
        string = string + "HTTP/1.1 {0} {1}\n".format(response.status_code, response.reason)
    except:
        string = string + "HTTP/1.1\n"
    #HEADERS
    for header, value in response.headers.items():
        string = string + "{0}: {1}\n".format(header, value)
    #Content
    string = string + "\n"
    for chunk in response.iter_content(chunk_size=128):
        string = string + chunk
    return string

def save_string(filename, content):
    with open(filename, "w") as text_file:
        text_file.write("%s" % content)

def new_log_line(position, req_num, results):
    status_code = ""
    try:
        status_code = results["response"].status_code
    except:
        status_code = "No status code" 
    length = ""
    try:
        length = results["response"].headers["Content-Length"]
    except:
        length = "-1" 
    return "{0}_{1} status code: {2} response length: {3} - {4}\n".format(str(position), str(req_num), status_code, length, results["hash"])

def make_request(request, line, timeout):
    req_res = {}
    request = request.replace("{}", line)
    req_res["hash"] = hashlib.md5(request).hexdigest()
    #parse raw request 
    r = HTTPRequest(request)
    url = r.raw_requestline.split()[1]
    r.headers["Content-Length"] = str(len(r.body))    
    headers = r.headers 
    data = r.body 
    try:
        response = requests.post(url, data=data, headers=headers, timeout=timeout, stream=True)
        string_response = response_to_string(response)
        req_res["response"] = response 
        req_res["string_response"] = string_response 
        req_res["request"] = request
    except:
        req_res = None

    return req_res

def fuzz(request, position, total, dict, output, fuzz_default, timeout):
    print "[*] Fuzzing input {0}...".format(position + 1)

    #replace inputs
    format = []
    for i in range(0, total):
        if i != position:
            format.append(fuzz_default)
        else:          
            format.append("{}")                  

    request = request.format(*tuple(format))

    #filename changes for each request
    lines = file_len(dict)
    req_num = 0 
    log = ""
    errors = 0
    #fuzz with the dictionary
    with open(dict, 'r') as f:
        for line in f:
            line = line.strip()
            req_num = req_num + 1
            results = make_request(request, line, timeout)
            if results != None:
                filename_res = "{0}/res/{1}_{2}_{3}".format(output, str(position), str(req_num), results["hash"])
                filename_req = "{0}/req/{1}_{2}_{3}".format(output, str(position), str(req_num), results["hash"])
                log = log + new_log_line(position, req_num, results)
                save_string(filename_req, results["request"])
                save_string(filename_res, results["string_response"])
            else:
                errors = errors + 1
                log = log + "{0}_{1} Invalid Request \"{2}\"\n".format(str(position), str(req_num), line)
            print "\rRequest {0} of {1} ({2} {3})".format(req_num, lines, errors, "error" if errors == 1 else "errors"),
            sys.stdout.flush()
        print "\n"
    return log 

def handle_template(template, param, dictionary, output, fuzz_default, timeout):
    #Count Number of template inputs
    f = open(template, 'r').read()
    print "[+] Load template {0}".format(template)
    inputs = f.count("{}")
    print "[+] Template inputs: {0}".format(inputs)

    if param > inputs:
        print "\n[-] Parameter set to {0} but template has only {1} inputs. Exiting...".format(param, inputs)
        sys.exit(-1)
        
    #Fuzz each input
    log_file = ""
    for i in range(0, inputs):
        if param < 0 or param - 1 == i:
            log_file = log_file + fuzz(f, i, inputs, dictionary, output, fuzz_default, timeout)
        else:
            print "\n[*] Ignoring input {0}".format(i+1),

    filename = output + "/results.log"
    save_string(filename, log_file)

def handle_template_dir(folder, param, dictionary, output, fuzz_default, timeout):
    print "[+] Template folder: {0}".format(folder)
    files = os.listdir(folder)
    print "[+] Number of templates to fuzz: {0}".format(len(files))
    #List files in the directory and use them as template
    for template in files:
        new_output = output + '/' + template 
        create_output(new_output)
        template = folder + '/' + template
        handle_template(template, param, dictionary, new_output, fuzz_default, timeout)

def create_output(o, req_res=True):
    #Ensure output directory does not exists
    if not os.path.exists(o):
        os.makedirs(o)
        if req_res:
            req_o = o + "/req"
            res_o = o + "/res"
            os.makedirs(req_o)
            os.makedirs(res_o)
    else:
        print "[-] {0} directory already exists, exiting...".format(o)
        sys.exit(-1)

def main():
    #Parse arguments 
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', action='store', dest='template', help='HTTP request template', required=True) 
    parser.add_argument('-d', action='store', dest='dictionary', help='Fuzzing dictionary', required=True)
    parser.add_argument('-o', action='store', dest='output', help='Output directory') 
    parser.add_argument('--param', action='store', dest='parameter', help='Fuzz just one parameter (if not set fuzz all of them)') 
    parser.add_argument('--timeout', action='store', dest='timeout', help='Time to stop waiting for a response in seconds (default to 0.1 seconds)') 
    parser.add_argument('--default', action='store', dest='default', help="Value used for the parameters that are not being fuzzed (if not set defaults to 'wubalubadub')") 
    args = parser.parse_args()
    template = args.template
    dictionary = args.dictionary
    output = args.output
    is_template_folder = os.path.isdir(template)
    param = int(args.parameter) if args.parameter != None else -1
    timeout = float(args.timeout) if args.timeout != None else 0.1
    fuzz_default = args.default if args.default != None else "wubalubadu"

    if output != None:
        create_output(output, req_res=not is_template_folder)
    else:
        print "[+] Output not defined, defaults to './output/'"
        o = "output"
        create_output(output, req_res=not is_template_folder)

    if is_template_folder:
       handle_template_dir(template, param, dictionary, output, fuzz_default, timeout) 
    else:
        handle_template(template, param, dictionary, output, fuzz_default, timeout)
    
if __name__ == "__main__":
    main()
