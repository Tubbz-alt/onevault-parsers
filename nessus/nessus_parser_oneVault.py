#!/usr/bin/env python3
# coding: utf-8

"""
A basic script to parse .nessus files into seperate host CSV files,
which are formatted to be uploaded into oneVault projects.

 - basic use: python3 nessus_to_oneVault.py myScanFile.nessus

The .nessus file is parsed and a CSV file for each host in the .nessus file
is created under the /output/ folder. These individual files can then be uploaded
into onevault.tech project assets.

Author: Scapecom 
Version: 1.0
project: onevault.tech

"""
import os
import csv
import sys
from sys import argv
import xml.etree.ElementTree as ET

try:
    parse_file = sys.argv[1]
except IndexError:
        print ('\nUsage: ' + argv[0] +' <nessus_file.nessus>\n')
        print ('*generated files placed under the "output" folder\n')
        sys.exit(2)

tree = ET.parse(parse_file)

data = []
new_host = ""
nessus_file = None

os.makedirs(os.path.dirname('output/'), exist_ok=True)

for host in tree.findall('Report/ReportHost'):
  ipaddr = host.find("HostProperties/tag/[@name='host-ip']").text

  for item in host.findall('ReportItem'):
    risk            = item.find('risk_factor').text
    summary         = item.find('synopsis').text
    details         = item.find('description').text
    remediation     = item.find('solution').text
    name            = item.get('pluginName')
    port            = item.get('port')
    port_protocol   = item.get('protocol')
  
    if (risk != 'None'):
        if (ipaddr != new_host):
            if nessus_file is not None:
                nessus_file.close()
            nessus_file = open('output/' + ipaddr + '_nessus_oneVault.csv', 'w')
            csvwriter = csv.writer(nessus_file)
            csvwriter.writerow(['ip Address', 'name', 'risk', 'port', 'port_protocol', 'summary', 'details', 'remediation'])
            
            new_host = ipaddr

        if (ipaddr == new_host):
            csvwriter.writerow([ipaddr, name, risk, port, port_protocol.upper(), summary, details, remediation])

            new_host = ipaddr

print ('\nCheckout the output folder for exported CSV files.\n')