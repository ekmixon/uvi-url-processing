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

        with open(url_extracted_data_file) as data_file:
            extracted_data = json.load(data_file)
            if extracted_data["uvi"]["experimental"]["other_identifiers"]["cve"]:
#                print("FOUND CVE")
                continue
            else:
                print(line)
#                print("NO CVE")

#            extracted_data={
#                "osv": {
#                    "published": info_date_string,
#                    "package": {
#                        "name": debian_package_name
#                        },
#                    "references": [ {
#                        "type": debian_advisory_type,
#                        "url": url
#                        } ]
#                    },
#                "uvi": {
#                    "vendor_name": "Debian",
#                    "product_name": "Linux",
#                    "experimental": {
#                        "package_name": debian_package_name,
#                        "package_affected": package_info,
#                        "advisory_type": debian_dsa_id,
#                        "vulnerability_status": info_vuln,
#                        "processed_timestamp": processed_timestamp,
#                        "uvi_script_version": uvi_script_version,
#                        "uvi_script_name": uvi_script_name,
#                        "other_identifiers": {
#                            "cve": data_cve
#                            }
#                        }
#                    }
#                }

            #print(json.dumps(extracted_data, indent=4, sort_keys=True))
