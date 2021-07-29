#!/usr/bin/env python3

import hashlib
# Requires Python 3.5 or later
from pathlib import Path

import requests
from requests.exceptions import RequestException
import json
import datetime
import sys

uvi_script_version = "0.0.3"
uvi_script_name = sys.argv[0]

#
# Processa file with a list of URLs
#
global_url_list = sys.argv[1]


#
# Get the ~/.uvi/config.json and read it into uvi_config
#
from pathlib import Path
home = str(Path.home())
config_file = home + '/.uvi/config.json'
with open(config_file) as config_data:
  uvi_config = json.load(config_data)
global_uvi_url_downloads = uvi_config["global"]["uvi_url_downloads_repo"] + "/data/"

#global_uvi_url_downloads = "/mnt/c/GitHub/uvi-url-downloads/data"

with open(global_url_list) as file:
    for line in file:
        already_seen = False
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
        url_directory_raw_data=url_directory + "/raw-data"

        if Path(url_directory_raw_data).is_dir():
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

            #
            # Request file data
            #
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

            #
            # Remove old txt file if exists
            #
            request_data_file_txt = url_directory + "/request.txt"
            if os.path.exists(request_data_file_txt):
                os.remove(request_data_file_txt)

            #
            # Response file data
            #
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

            #
            # Remove old txt file if exists
            #
            response_data_file_txt = url_directory + "/response.txt"
            if os.path.exists(response_data_file_txt):
                os.remove(response_data_file_txt)
