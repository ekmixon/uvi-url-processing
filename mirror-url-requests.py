#!/usr/bin/env python3

import hashlib
# Requires Python 3.5 or later
from pathlib import Path

import requests
from requests.exceptions import RequestException
import json
import datetime
#
# Processa file with a list of URLs
#
global_url_list = "./urls-to-process.txt"
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
            print("file directory already exists")
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

            request_data = url_directory + "/request.txt"
            f = open(request_data, "w")
            f.write("URL:" + url + "\n")
            f.write("TIMESTAMP:" + request_timestamp + "\n")
            f.write("REQUEST_METHOD:mirror-url-requests.py\n")
            f.close()

            response_data = url_directory + "/response.txt"
            f = open(response_data, "w")
            f.write("elapsed:" + str(response.elapsed) + "\n")
            f.write("is_redirect:" + str(response.is_redirect) + "\n")
            f.write("status_code:" + str(response.status_code) + "\n")
            f.write("url:" + response.url + "\n")
            f.write("response_file:" + response_file)
            f.close()
