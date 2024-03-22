#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
from argparse import RawTextHelpFormatter
from datetime import date
from timeit import default_timer as timer
from rich import print as rprint

#import aiohttp, asyncio
import httpx
import urllib.parse
import os.path
import zipfile
import json

url = "https://api.vulncheck.com/v3/backup/vulncheck-kev"

conn = 0
path = './archive/'
hdrs = { 'Accept': 'application/json' }
token = f''
params = { 'token': f'{token}' }
verbose = False

desc = f'A cmdline tool for VulnCheck KEV. (https://vulncheck.com/browse/kev)'
note = f'''

        VulnCheck KEV

        It is a community resource that enables security teams  to manage
        vulnerabilities and risk with additional context and evidence-based
        validation.

        For more information, see https://vulncheck.com/kev

'''

def timeit(func):
    """ Print time taken for a funtion execution """
    global verbose

    def timed(*args, **kwargs):
        stime = timer()
        result = func(*args, **kwargs)
        etime = timer()
        if verbose:
            rprint(f'\n [*] {func.__name__}(): completed within [{etime-stime:.4f} sec].\n ')
        return result
    return timed


def fetch(url, params, hdrs=None):
    global conn

    try: 
        resp = httpx.get(url, headers=hdrs, params=params)
    finally:
        conn += 1

    return resp


def getParams(data):
    """ Extract and return the params """

    fname = data[0].get('filename')
    d_url = data[0].get('url')

    strs = d_url.split('?')
    queryparams = d_url.split('?')

    #rprint(f' * {queryparams = }')

    link, qparams = d_url.split('?')
    #rprint(f'{link = }')
    #rprint(f'{qparams = }')
    params = urllib.parse.parse_qs(qparams)
    dparams = { k:v[0] for k,v in params.items() }

    return fname, link, dparams 



def usage():
    """ usage() function """
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawTextHelpFormatter, epilog=note)

    #parser.add_argument('urls', metavar='url', nargs='+', help='List of URL separated by space.')
    parser.add_argument('-e', dest='cve', metavar='<cve>', nargs='+', help='Specifying CVEs')
    #parser.add_argument('-k', action='store_true', help='Turn off SSL check.')
    parser.add_argument('-v', action='store_true', help='verbose output')

    return parser.parse_args()

@timeit
def main():
    """ main() function """
    global verbose
    global url, params, hdrs
    global path

    params = { 'token': f'{token}' }
    cve_list = []

    args = usage()
    verbose = True if args.v else False

    if args.cve:
        cves = args.cve

        for cve in cves:
            if not cve.lower().startswith('cve-'):
                cve = 'CVE-' + cve
            cve_list.append(cve.upper())

    print(f'')
    resp = fetch(url,params,hdrs)
    data = resp.json().get('data')

    filename, url_link, q_params = getParams(data)


    if os.path.isfile(path+filename):
        rprint(f' [*] File exists. Skip downloading.')
    else:
        rprint(f' [*] Download starts.')
        zfile = fetch(url_link,q_params)
        if zfile.status_code == httpx.codes.OK:
            with open(path+filename, mode='wb') as fp:
                fp.write(zfile.content)
            rprint(f' [*] Download completed.')
        else:
            rprint(f' [!] Error download from {url_link}.')


    latest = f'./latest.json'
    with zipfile.ZipFile(path+filename, 'r') as zp:
        if verbose:
            rprint(f' [*] Extracting JSON from zip file.')
        for f in zp.infolist():
            data = zp.read(f)
            with open(latest, 'wb') as fh:
                fh.write(data)
        if verbose:
            rprint(f' [*] Completed extract JSON.')

    with open(latest) as jh:
        vcdata = json.load(jh)


    rprint(f' [*] {len(vcdata) = } CVEs loaded.')

    if not args.cve:
        return

    print(f'')
    rprint(f' [*] Searching [ {cve_list = } ] ....')

    for search in cve_list:
        found = False
        for vuln in vcdata:
            cve = vuln['cve']
            if len(cve) > 1:
                rprint(f' * {cve = }')
            if cve[0] == search:
                found = True
                v = vuln
        else:
            if found:
                print(f'')
                rprint(f' [*] Found {v["cve"]}')
                rprint(f' [+] Vendor: {v["vendorProject"]}/{v["product"]}')
                rprint(f' [+] Desc: {v["shortDescription"]}')
                rprint(f' [+] Vuln: {v["vulnerabilityName"]}')
                rprint(f' [+] Date: {v["date_added"]}')
                cisa = v.get('cisa_date_added', 'None')
                rprint(f' [+] CISA: {cisa}')
                rprint(f' [+] Ransomeware: {v["knownRansomwareCampaignUse"]}')
                xdb = f'{len(v["vulncheck_xdb"])}'
                xpl = f'{len(v["vulncheck_reported_exploitation"])}'
                rprint(f' [+] XDB: {xdb}')
                rprint(f' [+] Exploit : {xpl}')
            else:
                print(f'')
                rprint(f' [*] {search} not found in VulnCheck KEV.')
 


if __name__ == "__main__":

    token = os.getenv('VC_TOKEN', default=None)

    if token is None:
        rprint(f' VC_TOKEN is not SET.')
    else:
        main()

