"""
posted in a comment in this issue: 
    https://github.com/nickovs/unificontrol/issues/12
"""

#!/usr/local/bin/python3.8
# -*- coding: utf-8 -*-
import sys
import base64
import json
from requests import Request, Session, packages
from requests.packages.urllib3.exceptions import InsecureRequestWarning

username = ''
password = ''
# unifi_url = 'https://ubnt.example.com'
# unifi_url = 'https://192.168.1.1:443' # running machine on local network, e.g.
unifi_url = 'https://127.0.0.1:443' # ssh'd into local machine, e.g. 
site = 'default'
post = 'POST'
put = 'PUT'
get = 'GET'
action = None
address = None
csrf_token = None
cookie_token = None
debug = False

tracked_headers = ['X-CSRF-TOKEN', 'CONTENT-TYPE', 'CONTENT-LENGTH', 'SET-COOKIE']
session = Session()

def callURL(verb, path, payload, parse_response=True, return_error=True):
    global csrf_token, debug, unifi_url, session

    url = unifi_url + path
    response = None
    try:
        packages.urllib3.disable_warnings(InsecureRequestWarning)
        if verb in (post, put):
            req = Request(verb, url, json=payload)
            if not csrf_token is None:
                print("Update CSRF Token")
                session.headers.update({'X-CSRF-Token': csrf_token})
                print("...done.")
            else:
                print("CSRF Token is None.")
            response = session.send(session.prepare_request(req), verify=False)
            headers = {'Content-Type': 'application/json'}
            #req_cookies = session.request.cookies
            resp_cookies = response.cookies
            resp_headers = response.headers
            req_headers = response.request.headers
            print("---")
            #print("COOKIES --> %s" % req_cookies)
            for r in req_headers:
                if r.upper() in tracked_headers and debug:
                    print("REQ HEADER  %s=%s" % (r, req_headers[r]))
            if debug:
                print("===")
                print("COOKIES <-- %s" % resp_cookies)
            for h in resp_headers:
                if h.upper() in tracked_headers:
                    if debug:
                        print("RESP HEADER --> %s: %s" % (h, resp_headers[h]))
                    if h.upper() == 'X-CSRF-TOKEN':
                        csrf_token = resp_headers[h]
                        if debug:
                            print("Token %s=%s saved." % (h, csrf_token))
                    elif h.upper() == 'SET-COOKIE':
                        cookie_token = resp_headers[h]
                        if debug:
                            print("Cookie %s=%s saved." % (h, cookie_token))
            if debug:
                print("COOKIE / CSRF TOKEN: %s/%s" % (cookie_token, csrf_token))
            print("Response status & reason: " + str(response.status_code) + " " + str(response.reason))
        print(response)
        if response.status_code != 200 and response.status_code != 204 and response.status_code !=201 and return_error:
            raise Exception("Error when requesting remote url %s [%s]:%s" % (path,  response.status_code, response.text))

        if parse_response:
            return response.text
        return None
    except Exception as e:
        # print("Unexpected error: ",sys.exc_info()[0])
        raise e
        # sys.exit(2)

def login():
    global username, password

    print("LOGIN")
    print("=====")
    payload = {'password': password, 'username': username}
    #print("PAYLOAD TO SEND=%s" % payload)
    #payload['strict'] = 'True'
    response = callURL('POST', '/api/auth/login', payload)
    #print(response.content)
    #print("-----------------------------------------")
    #print("JSON", response.json())
    print("\n")

def logout():
    global session

    print("LOGOUT")
    print("======")
    response = callURL('POST', '/logout', '')
    session.cookies.clear()

def listClients():
    global action, site

    login()

    print("LIST CLIENTS")
    print("============")
    response = callURL('POST', '/proxy/network/api/s/%s/stat/sta' % site, '')
    output = json.loads(response)
    # print(output)
    mac = None
    blocked = None
    name = None
    for client in output['data']:
    #   if isOnBlacklist(client):
        if True:
            if "name" in client:
                name = client['name']
                print("Name: %s" % client['name'])
            print("Is On Blacklist:",isOnBlacklist(client))
            if "ip" in client:
                print("IP: %s" % client['ip'])
            if "fixed_ip" in client:
                print("Fixed IP: %s" % client['fixed_ip'])
            if "mac" in client:
                mac = client['mac']
                print("MAC: %s" % mac)
            if "hostname" in client:
                print("Host name: %s" % client['hostname'])
            if "device_name" in client:
                print("Device name: %s" % client['device_name'])
            if "blocked" in client:
                print("Checking name/mac %s/%s" % (client.get('name') or '', mac))
                blocked = client['blocked']
                if action == 'block' and not blocked:
                    print("Blocking client with mac %s" % mac)
                    blockClient(mac)
                else:
                    print("Client with mac %s blocking status is %s" % (mac, blocked))
    
            print("---")
    print("\n")

def blockClient(mac):
    global site

    login()
    path = '/proxy/network/api/s/%s/cmd/stamgr' % site
    payload = {'cmd': 'block-sta', 'mac': mac}
    response = callURL('POST', path, payload)
    print("BLOCK RESPONSE")
    print(response)

def unblockClient(mac):
    global site

    path = '/proxy/network/api/s/%s/cmd/stamgr' % site
    payload = {'cmd': 'unblock-sta', 'mac': mac}
    response = callURL('POST', path, payload)
    print("UNBLOCK RESPONSE")

def kickClient(mac):
    """
    NOTE: 
        This errors out if the client is already blocked. 
        Client must be connected and unblocked for the kick to work
    """
    global site

    login()
    path = '/proxy/network/api/s/%s/cmd/stamgr' % site
    payload = {'cmd': 'kick-sta', 'mac': mac}
    response = callURL('POST', path, payload)
    print("KICK RESPONSE")
    print(response)

def disableSwitchPort(device_id: str, port_idx: int, portconf_id: str='608c2e7608906a06b18185f9'):
    """
    This is the payload the client sends:
    {"port_overrides":[{"name":"eth6","port_idx":7,"portconf_id":"608c2e7608906a06b18185f9","port_security_mac_address":[],"autoneg":true}]}

    Seen:
        608c2e7608906a06b18185f9: disable port
        ...TODO
    """
    global site
    login()
    path = f'/proxy/network/api/s/{site}/rest/device/{device_id}'
    payload = {
        "port_overrides":[
            {
                # "name":"eth6",
                "port_idx": port_idx,
                "portconf_id": portconf_id,
                # "port_security_mac_address":[],
                # "autoneg":True
            }
        ]
    }
    response = callURL('PUT', path, payload)
    print(f'DISABLED SWITCH {port_idx}')
    # print(response)


def enableSwitchPort(device_id: str, port_idx: int, portconf_id: str='608c2e7608906a06b18185f8'):
    """
    This is the payload the client sends:
    {"port_overrides":[{"name":"eth6","port_idx":7,"portconf_id":"608c2e7608906a06b18185f8","port_security_mac_address":[],"autoneg":true}]}
    Seen:
        608c2e7608906a06b18185f8: enable port
        ...TODO
    """
    global site
    login()
    path = f'/proxy/network/api/s/{site}/rest/device/{device_id}'
    payload = {
        "port_overrides":[
            {
                # "name":"eth6",
                "port_idx": port_idx,
                "portconf_id": portconf_id,
                # "port_security_mac_address":[],
                # "autoneg":True
            }
        ]
    }
    response = callURL('PUT', path, payload)
    print(f'ENABLED SWITCH {port_idx}')
    # print(response)

    
def isOnBlacklist(client):
    match = False
    if 'hostname' in client and ("MANOLO" in client['hostname'].upper() and "IPHONE" in client['hostname'].upper()):
        match = True
    if 'name' in client and ("MANOLO" in client['name'].upper() and "IPHONE" in client['name'].upper()):
        match = True
    return match

def noisOnBlacklist(client):
    match = False
    if 'hostname' in client and "NICK" in client['hostname'].upper():
        match = True
    if 'name' in client and "NICK" in client['name'].upper():
        match = True
    if 'hostname' in client and "LUKE" in client['hostname'].upper():
        match = True
    if 'name' in client and "LUKE" in client['name'].upper():
        match = True
    return match 

def usage():
    print("Usage: ./udmCheck.py [BLOCK|UNBLOCK] [MAC ADDRESS]")
    print("e.g.   ./udmCheck.py block")
    print("e.g.   ./udmCheck.py unblock aa:bb:cc:dd:ee:ff")

#
# MAIN PROGRAMME
#
def main():
    # MACS TO BLOCK:
    BLOCK_LIST = ['aa:aa:aa:aa:aa:aa', 'aa:aa:aa:aa:bb:bb' ]


    argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        usage()
        # sys.exit(1)
    else:
        login()
        if len(argv) ==  1 and argv[0].upper() == 'BLOCK':
            action = 'block'
            listClients()
        elif len(argv) ==  2 and argv[0].upper() == 'UNBLOCK':
            action = 'unblock'
            address = argv[1].lower()
            unblockClient(address)
        elif len(argv) ==  1 and argv[0].upper() == 'BLOCKLIST':
            for addr in BLOCK_LIST:
                blockClient(addr)
        elif len(argv) ==  1 and argv[0].upper() == 'UNBLOCKLIST':
            for addr in BLOCK_LIST:
                unblockClient(addr)
    logout()
    # sys.exit(0)
