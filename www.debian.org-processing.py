#!/usr/bin/env python3

script_version = "0.0.1"
script_name = "www.debian.org-processing.py"

import hashlib
# Requires Python 3.5 or later
from pathlib import Path

from requests.exceptions import RequestException
import json
import datetime
import re
import calendar

# Kurt knows about Beautifulsoup and scrappy but Kurt also likes regex and state machines and DSA's are shockingly well formatted/regular.

#
# Processa file with a list of URLs
#
global_url_list = "./urls-to-process.txt"
global_security_url_downloads = "/mnt/c/GitHub/security-url-downloads/data"

with open(global_url_list) as file:
    for line in file:
        timestamp = datetime.datetime.utcnow() # <-- get time in UTC
        processed_timestamp = timestamp.isoformat("T") + "Z"
        url = line.rstrip()
        url_bytes = url.encode()
        h = hashlib.sha512()
        h.update(url_bytes)
        url_hash = h.hexdigest()
        url_hash_1 = url_hash[0:2]
        url_hash_2 = url_hash[2:4]
        url_hash_3 = url_hash[4:6]
        url_hash_4 = url_hash[6:8]

        url_directory = global_security_url_downloads + "/" + url_hash_1 + "/" + url_hash_2 + "/" + url_hash_3 + "/" + url_hash_4 + "/" + url_hash
        url_directory_raw_data = url_directory + "/raw-data"
        url_raw_data = url_directory_raw_data + "/server_response.data"
        url_extracted_data = url_directory + "/extracted_data.txt"

        # Version data is split across lines
#<p>For the oldstable distribution (stretch), these problems have been fixed
#in version 3.17.0+ds1-5+deb9u1.</p>
#<p>For the stable distribution (buster), these problems have been fixed in
#version 3.18.0+ds2-1+deb10u1.</p>


        with open(url_raw_data) as data_file:
            #
            # ID:DSA
            # ID:CVE
            # Debian package name
            data_cve = []
            date_reported_flag = False
            vuln_flag = False
            for data_line in data_file:
                data_line = data_line.rstrip()
                # Get the DSA if exists and the Debian package name
                if re.match("^  <title>Debian -- Security Information -- .*", data_line):
                    # we only want the first occurance
                    info = data_line
                    info = re.sub("^  <title>Debian -- Security Information -- ", "", info)
                    info = re.sub(" </title>$", "", info)
                    # split it, DSA-X and name, or just name for old stuff
                    debian_info = info.split(" ", 1)

                    if len(debian_info) == 1:
                        debian_advisory_type="preDSA"
                        debian_package_name = debian_info[0]
                        debian_dsa_id = False

                    if len(debian_info) == 2:
                        debian_advisory_type="DSA"
                        debian_dsa_id = debian_info[0]
                        debian_package_name = debian_info[1]

                # Get any CVE ID's in the file
                tmp_data_cve = re.findall(r'CVE-[0-9]+-[0-9]+', data_line)
                data_cve.extend(tmp_data_cve)
                # Get the vulnerability state - state machine because one line at a time, look for the date reported, then read it
                if vuln_flag == True:
                    info_vuln = re.sub("^\s*<dd class=\"warning\">", "", data_line)
                    info_vuln = re.sub("</dd>$", "", info_date)
                    # print(info_date_string)
                    info_vuln = "yes"
                    vuln_flag = False
                if re.match("^<dt>Vulnerable:</dt>$", data_line):
                    vuln_flag = True

                # Get the date reported - state machine because one line at a time, look for the date reported, then read it
                if date_reported_flag == True:
                    info_date = re.sub("^\s*<dd>", "", data_line)
                    info_date = re.sub("</dd>$", "", info_date)
                    info_date_parts = info_date.split(" ")
                    # TODO: pad out the month/day to two digits
                    info_date_year = str(info_date_parts[2])
                    info_date_month = str(list(calendar.month_abbr).index(info_date_parts[1])).rjust(2, "0")
                    info_date_date = str(info_date_parts[0]).rjust(2, "0")
                    info_date_string = info_date_year + "-" + info_date_month + "-" + info_date_date
                    # print(info_date_string)
                    date_reported_flag = False
                if re.match("^<dt>Date Reported:</dt>$", data_line):
                    date_reported_flag = True
            # Collapse the CVE list
            data_cve = list(set(data_cve))

            #
            # Final data
            #

            # debian_advisory_type - preDSA / DSA
            # debian_dsa_id - DSA-ID / False (preDSA)
            # debian_package_name - string
            # data_cve - list of CVEs
            # url - string
            # info_vuln - Yes or False
            # info_date_string - YYYY-M-D
            # processed_timestamp - YYYY-MM-DD-HH-MM-SS
            # script_version - string
            # script_name - string

            # Try to use standards where possible e.g. OSV
            extracted_data={
                "osv": {
                    "published": info_date_string,
                    "package": {
                        "name": debian_package_name
                        },
                    "references": [ {
                        "type": debian_advisory_type,
                        "url": url
                        } ]
                    },
                "uvi": {
                    "vendor_name": "Debian",
                    "product_name": debian_package_name,
                    "experimental": {
                        "advisory_type": debian_dsa_id,
                        "vulnerability_status": info_vuln,
                        "processed_timestamp": processed_timestamp,
                        "script_version": script_version,
                        "script_name": script_name,
                        "other_identifiers": {
                            "cve": data_cve
                            }
                        }
                    }
                }
            print("*****************")
            print(json.dumps(extracted_data, indent=4, sort_keys=True))