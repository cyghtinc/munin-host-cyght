import configparser
import ipaddress
import os
import re
import requests
import pymisp
import time
import csv
import argparse

# Read the config file
config = configparser.ConfigParser()
try:
    config.read('./misp-ip-search.ini')
    # MISP config
    has_MISP = False
    if config.has_section('MISP'):
        MISP_URL = config.get('MISP', 'MISP_URL').replace('\'','')
        MISP_AUTH_KEY = config.get('MISP', 'MISP_AUTH_KEY').replace('\'','')
    if MISP_URL == '' or MISP_AUTH_KEY == '':
        print("[E] Please provide the url and the api key in 'misp-ip-search.ini'")
        exit(1)
except Exception as e:
    print("[E] Config file 'misp-ip-search.ini' not found or missing field - check the current misp-ip-search.ini template if fields have "
            "changed or add the missing field manually")
    exit(1)

def is_ip(value):
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$'
    if re.match(ip_pattern, value):
        return True
    return False

def is_private(ip):
    ip = ipaddress.ip_address(ip)
    return ip.is_private

def make_link_to_event(eventid):
    # TODO: Make sure that there's a trailing slash on the MISP_SERVER param
    return("<" + MISP_URL + "events/view/" + str(eventid) + "|Event " + str(eventid) + ">")

def make_timestamp(ts):
    return("<!date^" + str(int(ts.timestamp())) + "^{date_num} {time}|timestamp>" )

def defang(indicator):
    return (indicator.replace(".", "[.]")).replace("://", "[://]")

def filter_attribute(attribute, indicator, attribute_types):
    # Determine if the indicator should be included, True/False
    if attribute['type'] not in attribute_types:
        return(False)
    if (attribute['value']!=indicator):
        return(False)
    
    return(True)

def render_results(result_object, indicator, attribute_types):
    # Make sure that we have a list of results, otherwise error
    if (type(result_object)!=list):
        return("*Error parsing MISP results*\n")
    
    # Check if the results are empty
    if (len(result_object)==0):
        return("No results found\n")

    output =""
     # Step through each attribute in the root level
    for i in result_object:
        # Check the published flag for the event
        published_flag = "~Published~"
        if (i['published']==True):
            published_flag = "Published"           
        output += "*" + make_link_to_event(i['id']) + "\n" + published_flag + "\n" + str(i['info']) + "*\n"

    return(output)

def misp_search_ip(ip):
    update_limit()
    requests.packages.urllib3.disable_warnings()  # I don't care
    attribute_types = ["ip-src","ip-dst"]
    misp = pymisp.PyMISP(MISP_URL, MISP_AUTH_KEY, False, False, proxies={},cert=None,auth=None,tool='Cyght : Online ip checker')
    result = misp.search(value=ip, type_attribute= ["ip-src","ip-dst"], limit=11, published=True, to_ids=True, deleted=False, pythonify=True)          
    return(render_results(result, ip, attribute_types))

def read_limit():
    if not os.path.exists('./limit.txt'):
        limit_file = open('./limit.txt', "w")
        limit_file.write('0')
        limit_file.close
    limit_file = open('./limit.txt', "r")
    limit = int(limit_file.readline().strip())
    limit_file.close()
    return limit

def update_limit():
    limit = read_limit()
    limit_file = open('./limit.txt', "w")
    if limit == 15:
        update = 0
    else:
        update = limit+1
    limit_file.write(str(update))
    limit_file.close()
    return update

# Initialize parser
parser = argparse.ArgumentParser(description='MISP Online IP Checker (Limit Of 15 IP Addresses Per 15 Minutes)')
 
# Adding optional argument
parser.add_argument("-f", help = 'File to process (IP adress line by line', metavar='path',default='')
parser.add_argument("-i", help = 'Single IP adress', metavar='IP address',default='')

# Read arguments from command line
args = parser.parse_args()
 
# Check args
if args.f != '' and args.i !='':
    print("[E] Please provide only an input file with '-f' input file or a single ip address with '-i' ip address\n")
    input('Press any key to exit\n')
    parser.print_help()
    exit(1)
if args.f == '' and args.i =='':
    print("[E] Please provide an input file with '-f' input file or a single ip address with '-i' ip address\n")
    input('Press any key to exit\n')
    parser.print_help()
    exit(1)
if args.f != '' and not os.path.exists(args.f):
    print("[E] Cannot find input file {0}".format(args.f) + ", please Enter the full path")
    input('Press any key to exit\n')
    exit(1)
if args.f != '' and not args.f.__contains__('.txt'):
    print("[E] Please provide a txt File")
    input('Press any key to exit\n')
    exit(1)

# Scan input file
if args.f != '':
    f = open(args.f, "r")
    lines = f.readlines()

    with open('results.csv', 'a', newline='') as file: 
        writer = csv.writer(file)
        writer.writerow(["IP", "Private", "Found On","Error"]) #prepare titles for the csv file
    for line in lines:
        with open('results.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            ip = line.strip()
            if not is_ip:
                writer.writerow([ip,"" , "","Not a valid IP"])
                continue
            if is_private(ip):
                writer.writerow([ip,"True" , "",""])
                continue
            if read_limit() == 15: #we have a limit of 15 req for 15 min
                print('We have reached the Limit, sleeping for 15 minutes (please dont exit)...')
                time.sleep(900)
                print('Wake up..')
                
            info = misp_search_ip(line.strip())
            if info == "*Error parsing MISP results*\n":
                writer.writerow([ip,"False" , "",info.strip()])
            elif info == "No results found\n":
                writer.writerow([ip,"False" , "",""])
            else:
                writer.writerow([ip,"False", info,""])
            print('Requests sent (for valid and non-private addresses) in the current limit: ' +str(read_limit())+'\n')
    f.close()
    print('End of Scan..')
    input('Press any key to exit')
    exit(0)

# Case that the single IP address is not a valid IP address
if not is_ip(args.i):
    print("[E] Please a valid IP address")
    input('Press any key to exit\n')
    exit(1)

# Case that the single IP address is private
if not is_private(args.i):
    print(args.i + 'is a private address.')
    input('Press any key to exit\n')
    exit(0)
# Check only a single IP address
if read_limit() == 15:
    print('We have reached the Limit, sleeping for 15 minutes (please dont exit)...')
    time.sleep(900)
    print('Wake up..')
info = misp_search_ip(args.i)
print(info)
input('Press any key to exit\n')

