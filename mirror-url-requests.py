#!/usr/bin/env python3

import hashlib
# Requires Python 3.5 or later
from pathlib import Path

import requests
from requests.exceptions import RequestException
import json
import datetime
import sys

uvi_script_version = "0.0.2"
uvi_script_name = sys.argv[0]

#
# Processa file with a list of URLs
#
global_url_list = sys.argv[1]
global_security_url_downloads = "/mnt/c/GitHub/security-url-downloads/data"

with open(global_url_list) as file:
    for line in file:
        already_seen = False
        print("processing: " + line)
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
        url_directory_raw_data=url_directory + "/raw-data"

        if Path(url_directory_raw_data).is_dir():
            print("file directory already exists: " + url_directory_raw_data)
            already_seen = True
        else:
            Path(url_directory_raw_data).mkdir(parents=True, exist_ok=True)


        # if already_seen == True:
        #
        # Logic to check timestamp and get again if over X timestamp

        if already_seen == False:
            timestamp = datetime.datetime.utcnow() # <-- get time in UTC
            request_timestamp = timestamp.isoformat("T") + "Z"

            # get file
            response = requests.get(url, allow_redirects=True)
            #response_dict = json.loads(response.text)
            response_file = url_directory_raw_data + "/server_response.data"
            f = open(response_file, "wb")
            f.write(response.content)
            f.close()

            request_data_file = url_directory + "/request.json"
            request_data = {
                "URL_requested": url,
                "TIMESTAMP": request_timestamp,
                "uvi_script_name": uvi_script_name,
                "uvi_script_version": uvi_script_version
            }
            f = open(request_data_file, "w")
            f.write(json.dumps(request_data, indent=4, sort_keys=True))
            f.close()

            response_data_file = url_directory + "/response.json"
            f = open(response_data_file, "w")
            response_data = {
                "elapsed": str(response.elapsed),
                "is_redirect": str(response.is_redirect),
                "status_code": str(response.status_code),
                "url": response.url,
                "response_file": response_file
            }
            f.write(json.dumps(response_data, indent=4, sort_keys=True))
            f.close()
