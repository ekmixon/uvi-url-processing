#!/usr/bin/env python3

import sys

uvi_script_version = "0.0.6"
uvi_script_name = sys.argv[0]

import hashlib
# Requires Python 3.5 or later
from pathlib import Path

from requests.exceptions import RequestException
import json
import datetime
import re
import calendar
import scrapy
from bs4 import BeautifulSoup

# Kurt knows about Beautifulsoup and scrappy but Kurt also likes regex and state machines and DSA's are shockingly well formatted/regular.

#
# Processa file with a list of URLs
#
global_url_list = sys.argv[1]
global_uvi_url_downloads = "/mnt/c/GitHub/uvi-url-downloads/data"


with open(global_url_list) as file:
    for line in file:
        # TODO: add check for blank line and ignore?
        # "" cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
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

        url_directory = global_uvi_url_downloads + "/" + url_hash_1 + "/" + url_hash_2 + "/" + url_hash_3 + "/" + url_hash_4 + "/" + url_hash
        url_directory_raw_data = url_directory + "/raw-data"
        url_raw_data = url_directory_raw_data + "/server_response.data"
        url_extracted_data_file = url_directory + "/extracted_data.json"

        # Version data is split across lines, 2-3 linmes, and can be multiple packages/versions within a line so we need to use scrapy, also differing fixed/unfixed/etc.

# TODO: scrapy to process document
# scrapy shell https://www.debian.org/security/2009/dsa-1907
# response.xpath("//*[contains(text(), 'these problems have been fixed in version')]").getall()
# ['<p>For the stable distribution (lenny), these problems have been fixed in version\n72+dfsg-5~lenny3.</p>',
# '<p>For the unstable distribution (sid) these problems have been fixed in version\n85+dfsg-4.1</p>']
# TODO: remove line return(s) and extract the distriburtion name, and the fixed in version X

        with open(url_raw_data) as data_file1:
            soup = BeautifulSoup(data_file1, "html.parser")
            #print(soup.title)
            paragraphs = soup.findAll('p')
            package_info=[]

            for entry in paragraphs:
                string_data = str(entry)
                string_data = string_data.replace('\n', ' ')
                # (old stable|oldstable|stable|testing|unstable|upcoming)
                if re.match("^<p>For the (old stable|oldstable|stable|testing|unstable|upcoming) (.+)", string_data):
                    print(string_data)
                    package_info_listing={}
                    string_data = re.sub("^<p>", "", string_data)
                    string_data = re.sub("</p>$", "", string_data)

                    # Some advisories have no distro name listed https://www.debian.org/security/2002/dsa-115

                    if re.match(".*\(.*\).*", string_data):
                        distro = re.findall("\(.*\)", string_data)
                        # Handle multiple???
                        distro_name = re.sub("^\(", "", distro[0])
                        distro_name = re.sub("\)$", "", distro_name)
                    else:
                        # add better parsing here but we'd need to map "testing" to the date to get the version? Just use "Debian testing as of Y-M-D"?
                        distro_name = "UNKNOWN"

                    fixed_version = re.sub(".* (this|these) (problem|problems) (have|has) been fixed in version ", "", string_data)
                    fixed_version = re.sub("\.$", "", fixed_version)

                    package_info_listing={
                        "distribution_affected": distro_name,
                        "fixed in": fixed_version
                    }
                    package_info.append(package_info_listing)

        with open(url_raw_data) as data_file:
            #
            # ID:DSA
            # ID:CVE
            # Debian package name
            data_cve = []
            date_reported_flag = False
            vuln_flag = False
            stable_flag = False
            oldstable_flag = False
            unstable_flag = False
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
                    if info_date == "undated":
                        print("undated")
                        info_date_string = "UNKNOWN"
                        date_reported_flag = False
                    else:
                        info_date_parts = info_date.split(" ")
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
            # uvi_script_version - string
            # uvi_script_name - string

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
                    "product_name": "Linux",
                    "experimental": {
                        "package_name": debian_package_name,
                        "package_affected": package_info,
                        "advisory_type": debian_dsa_id,
                        "vulnerability_status": info_vuln,
                        "processed_timestamp": processed_timestamp,
                        "uvi_script_version": uvi_script_version,
                        "uvi_script_name": uvi_script_name,
                        "other_identifiers": {
                            "cve": data_cve
                            }
                        }
                    }
                }
            #print(json.dumps(extracted_data, indent=4, sort_keys=True))

            f = open(url_extracted_data_file, "w")
            f.write(json.dumps(extracted_data, indent=4, sort_keys=True))
            f.close()
            print(json.dumps(extracted_data, indent=4, sort_keys=True))
