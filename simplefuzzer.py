#!/usr/bin/env python

#TODO refactor code
import argparse, os, requests, sys, hashlib, shutil
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

#class for parsing HTTP raw request
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        self.body = ''
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
    string = ''
    #HTTP 
    try:
        string = string + 'HTTP/1.1 {0} {1}\n'.format(response.status_code, response.reason)
    except:
        string = string + 'HTTP/1.1\n'
    #HEADERS
    for header, value in response.headers.items():
        string = string + '{0}: {1}\n'.format(header, value)
    #Content
    string = string + '\n'
    for chunk in response.iter_content(chunk_size=128):
        string = string + chunk
    return string

def save_string(filename, content):
    with open(filename, 'w') as text_file:
        text_file.write('%s' % content)

def new_log_line(position, req_num, dict_name, payload, results):
    status_code = ''
    try:
        status_code = results['response'].status_code
    except:
        status_code = 'No status code' 
    length = ''
    try:
        length = results['response'].headers['Content-Length']
    except:
        length = '-1' 
    return '[{0}_{1} {2}] status code: {3} - response length: {4} - {5} - {6}\n'.format(str(position), str(req_num), dict_name, status_code, length, payload, results['hash'])

def make_request(request, line, timeout):
    req_res = {}
    request = request.replace('{}', line)
    req_res['hash'] = hashlib.md5(request).hexdigest()
    #parse raw request 
    r = HTTPRequest(request)
    url = r.raw_requestline.split()[1]
    r.headers['Content-Length'] = str(len(r.body))    
    headers = r.headers 
    data = r.body 
    try:
        response = requests.post(url, data=data, headers=headers, timeout=timeout, stream=True)
        string_response = response_to_string(response)
        req_res['response'] = response 
        req_res['string_response'] = string_response 
        req_res['request'] = request
        req_res['error'] = False
    except Exception, e:
        req_res['error_message'] = e
        req_res['error'] = True

    return req_res

def fuzz(request, position, total, dict, dict_output, output, fuzz_default, timeout):
    print '[*] Fuzzing input {0}...'.format(position + 1)

    #replace inputs
    format = []
    for i in range(0, total):
        if i != position:
            format.append(fuzz_default)
        else:          
            format.append('{}')                  

    request = request.format(*tuple(format))

    #filename changes for each request
    dict_name = dict.split('/')[-1]
    lines = file_len(dict)
    req_num = 0 
    log = ''
    errors = 0
    #fuzz with the dictionary
    with open(dict, 'r') as f:
        for line in f:
            line = line.strip()
            req_num = req_num + 1
            results = make_request(request, line, timeout)
            if not results['error']:
                filename_res = '{0}/res/{1}{2}_{3}_{4}'.format(output, dict_output, str(position), str(req_num), results['hash'])
                filename_req = '{0}/req/{1}{2}_{3}_{4}'.format(output, dict_output, str(position), str(req_num), results['hash'])
                log = log + new_log_line(position, req_num, dict_name, line, results)
                save_string(filename_req, results['request'])
                save_string(filename_res, results['string_response'])
            else:
                errors = errors + 1
                log = log + '[{0}_{1} {2}] Error: {3} - \"{4}\"\n'.format(str(position), str(req_num), dict_name,results['error_message'], line)
            print '\rRequest {0} of {1} ({2} {3})'.format(req_num, lines, errors, 'error' if errors == 1 else 'errors'),
            sys.stdout.flush()
        print '\n'
    return log 

def fuzz_with_dictionary(f, i, inputs, dictionary_path, output, fuzz_default, timeout):
    log = ''
    files = os.listdir(dictionary_path)
    for dictionary in files:
        print '[+] Dictionary: {0}'.format(dictionary)
        dict_path = dictionary_path + '/' + dictionary
        dict_req_path = output + '/req/' + dictionary 
        dict_res_path = output + '/res/' + dictionary 
        if not os.path.exists(dict_req_path):
            os.makedirs(dict_req_path)
        if not os.path.exists(dict_res_path):
            os.makedirs(dict_res_path)
        dict_name = '{0}/'.format(dict_path.split('/')[-1]) 
        new_log = fuzz(f, i, inputs, dict_path, dict_name, output, fuzz_default, timeout)
        log = log + new_log
    return log

def handle_template(template, param, dictionary, output, fuzz_default, timeout):
    #Count Number of template inputs
    f = open(template, 'r').read()
    print '[+] Load template {0}'.format(template)
    inputs = f.count('{}')
    print '[+] Template inputs: {0}'.format(inputs)

    if param > inputs:
        print '\n[-] Parameter set to {0} but template has only {1} inputs. Exiting...'.format(param, inputs)
        sys.exit(-1)

    #Fuzz each input
    log_file = ''
    for i in range(0, inputs):
        if param < 0 or param - 1 == i:
            is_dictionary_folder = os.path.isdir(dictionary)
            if is_dictionary_folder:
                new_line = fuzz_with_dictionary(f, i, inputs, dictionary, output, fuzz_default, timeout)
                log_file = log_file + new_line 
            else:
                new_line = fuzz(f, i, inputs, dictionary, '', output, fuzz_default, timeout)
                log_file = log_file + new_line 
        else:
            print '\n[*] Ignoring input {0}'.format(i+1),

    filename = output + '/results.log'
    save_string(filename, log_file)

def handle_template_dir(folder, param, dictionary, output, fuzz_default, timeout):
    print '[+] Template folder: {0}'.format(folder)
    files = os.listdir(folder)
    print '[+] Number of templates to fuzz: {0}'.format(len(files))
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
            req_o = o + '/req'
            res_o = o + '/res'
            os.makedirs(req_o)
            os.makedirs(res_o)
    else:
        print '[-] {0} directory already exists, exiting...'.format(o)
        print 'Do you want to delete it? [y/N]',
        choice = raw_input().lower()
        if choice == 'y':
            shutil.rmtree(o)
            create_output(o, req_res)
        else:
            sys.exit(-1)

def handle_fuzzer(args):
    #parse arguments
    template = args.template
    dictionary = args.dictionary
    output = args.output
    is_template_folder = os.path.isdir(template)
    param = int(args.parameter) if args.parameter != None else -1
    timeout = float(args.timeout) if args.timeout != None else 0.5
    fuzz_default = args.default if args.default != None else 'wubalubadu'

    if output != None:
        create_output(output, req_res=not is_template_folder)
    else:
        print '[+] Output not defined, defaults to \'./output/\''
        output = 'output'
        create_output(output, req_res=not is_template_folder)

    #perform fuzzing
    if is_template_folder:
       handle_template_dir(template, param, dictionary, output, fuzz_default, timeout) 
    else:
        handle_template(template, param, dictionary, output, fuzz_default, timeout)

def handle_request(args):
    #parse arguments
    template = args.request
    timeout = float(args.timeout) if args.timeout != None else 0.5

    #perform requests
    request = open(template, 'r').read()
    results = make_request(request, '', timeout)

    if not results['error']:
        print results['string_response']
    else:
        print results['error_message']

def add_fuzzer_params(subparser):
    parser = subparser.add_parser('fuzzer', help='Fuzz a template given a dictionary')
    parser.add_argument('-t', action='store', dest='template', help='HTTP request template', required=True) 
    parser.add_argument('-d', action='store', dest='dictionary', help='Fuzzing dictionary', required=True)
    parser.add_argument('-o', action='store', dest='output', help='Output directory') 
    parser.add_argument('--param', action='store', dest='parameter', help='Fuzz just one parameter (if not set fuzz all of them)') 
    parser.add_argument('--timeout', action='store', dest='timeout', help='Time to stop waiting for a response in seconds (default to 0.1 seconds)') 
    parser.add_argument('--default', action='store', dest='default', help='Value used for the parameters that are not being fuzzed (if not set defaults to \'wubalubadub\')') 
 
def add_request_params(subparser):
    parser = subparser.add_parser('request', help='Send a raw HTTP request')
    parser.add_argument('-r', action='store', dest='request', help='HTTP request', required=True) 
    parser.add_argument('--timeout', action='store', dest='timeout', help='Time to stop waiting for a response in seconds (default to 0.1 seconds)') 

def main():
    parser = argparse.ArgumentParser(description='A simple HTTP fuzzer')
    subparsers = parser.add_subparsers(help='Program mode: request/fuzzer', dest='mode')
    
    add_request_params(subparsers)
    add_fuzzer_params(subparsers)

    args = parser.parse_args()

    if args.mode == 'request':
        handle_request(args)
    elif args.mode == 'fuzzer':
        handle_fuzzer(args)
    else:
        parser.print_usage()

if __name__ == '__main__':
    main()
