from pymisp import PyMISP
import time

misp_url = 'https://misppriv.circl.lu'
misp_key = 'Ev0eihJb8VasYZXTLy5Oc5uhHesUIv9CKqxmAN3f'
misp_verifycert = False

#PyMISP(m_url, m_auth_key, args.verifycert, debug=args.debug, proxies={},cert=None,auth=None,tool='Munin : Online hash checker')
misp = PyMISP(misp_url,misp_key,misp_verifycert,debug=False,proxies={},cert=None,auth=None,tool='Shay IP search')
counter = 0

f = open("./combined-unique.txt", "r")
lines = f.readlines()
for line in lines:
    complex_query = misp.build_complex_query(or_parameters=[line])
    events = misp.search(value=complex_query,pythonify=True)
    counter += 1
#    print (events)
    if len(events) != 0:
        print(line)
    for e in events:
        print (e)
    if counter % 4 == 0:
        time.sleep(60)
