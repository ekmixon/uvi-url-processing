#!/usr/bin/#!/usr/bin/env python3

# CSAF (TODO LATER)
# https://github.com/oasis-tcs/csaf/tree/master/csaf_2.0


# For Debian/RedHat/etc CVE just assigns a vendor_name of "n/a" and uses the package name/version which is not globally unique and will break so we set vendor_name as "Debian Linux foo"

# CVE4
CVE4 = {
  "data_type": "CVE",
  "data_format": "MITRE",
  "data_version": "4.0",
  "CVE_data_meta": {
    "ID": uvi_data_cve_id,
  },
  "affects": {
    "vendor": {
      "vendor_data": [
        {
          "vendor_name": uvi_data_vendor_name + " " + uvi_data_product_name + " " + uvi_data_product_version,
          "product": {
            "product_data": [
              {
                "product_name": uvi_data_package_name,
                "version": {
                  "version_data": [
                    {
                      "version_value": "<" + uvi_data_package_name_fixed
                    }
                  ]
                }
              }
            ]
          }
        }
      ]
    }
  },
  "problemtype": {
    "problemtype_data": [
      {
        "description": [
          {
            "lang": "eng",
            "value": uvi_data_vuln_type
          }
        ]
      }
    ]
  },
  "references": {
    "reference_data": [
      {
        "url": uvi_data_reference_url
      }
    ]
  },
  "description": {
    "description_data": [
      {
        "lang": "eng",
        "value": uvi_data_vuln_description
      }
    ]
  }
}

# OSV
# https://osv.dev/docs/#tag/vulnerability_schema
#
OSV = {
  "id": "string",
  "published": uvi_advisory_timestamp",
  "aliases": [
    uvi_data_advisory_id,
    uvi_data_cve_id
  ],
  "package": {
    "name": uvi_data_package_name,
    "ecosystem": uvi_data_vendor_name + " " + uvi_data_product_name + " " + uvi_data_product_version
  },
  "summary": uvi_data_vuln_description,
  "affects": {
    "ranges": [
      {
        "fixed":  "<" + uvi_data_package_name_fixed
      }
    ]
  },
  "references": [
    {
      "type": "NONE",
      "url": uvi_data_reference_url
    }
  ]
}
