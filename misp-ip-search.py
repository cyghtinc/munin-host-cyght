import ipaddress
import re
import requests
import pymisp #pip install pymisp
import time
import csv

misp_url = 'https://misppriv.circl.lu'
misp_key = 'Ev0eihJb8VasYZXTLy5Oc5uhHesUIv9CKqxmAN3f'
misp_verifycert = False

# #PyMISP(m_url, m_auth_key, args.verifycert, debug=args.debug, proxies={},cert=None,auth=None,tool='Munin : Online hash checker')
# misp = PyMISP(misp_url,misp_key,misp_verifycert,debug=False,proxies={},cert=None,auth=None,tool='Cyght:  Online IP checker')
# counter = 0
# f = open("./combined-unique.txt", "r")
# lines = f.readlines()
# for line in lines:
#     complex_query = misp.build_complex_query(or_parameters=[line])
#     events = misp.search(value=complex_query,pythonify=True)
#     counter += 1
# #    print (events)
#     if len(events) != 0:
#         print(line)
#     for e in events:
#         print (e)
#     if counter % 4 == 0:
#         time.sleep(60)

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
    return("<" + misp_url + "events/view/" + str(eventid) + "|Event " + str(eventid) + ">")

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
    requests.packages.urllib3.disable_warnings()  # I don't care
    attribute_types = ["ip-src","ip-dst"]
    misp = pymisp.PyMISP(misp_url, misp_key, False, False, proxies={},cert=None,auth=None,tool='Cyght : Online ip checker')
    result = misp.search(value=ip, type_attribute= ["ip-src","ip-dst"], limit=11, published=True, to_ids=True, deleted=False, pythonify=True)          
    return(render_results(result, ip, attribute_types))

f = open("./combined-unique.txt", "r")
limit_counter = 1
lines = f.readlines()

with open('results.csv', 'a', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["IP", "Private", "Found On","Error"])

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
        if limit_counter == 16:
            limit_counter = 1
            print('sleeping')
            time.sleep(900)
            print('wake up')
            
        info = misp_search_ip(line.strip())
        if info == "*Error parsing MISP results*\n":
            writer.writerow([ip,"False" , "",info.strip()])
        elif info == "No results found\n":
            writer.writerow([ip,"False" , "",""])
        else:
            writer.writerow([ip,"False", info,""])
        print('counter: ' +str(limit_counter)+'\n')
        limit_counter += 1
f.close()
