###########################################################################
#
# constants.py - Constants for vigiles-openwrt scripts
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
###########################################################################


DOWNLOAD_SBOM_FORMATS = ("cyclonedx", "spdx", "spdx-lite")

DOWNLOAD_SBOM_OPTIONS = {
    "cyclonedx": {
        "file_types": ("json", "xml"),
        "versions": ("1.7", "1.6", "1.5", "1.4", "1.3", "1.2", "1.1"),
    },
    "spdx": {
        "file_types": ("json", "xml", "yaml", "tag", "xlsx", "xls", "rdfxml"),
        "versions": ("2.3", "2.2"),
    },
    "spdx-lite": {
        "file_types": ("json", "xml", "yaml", "tag", "xlsx", "xls", "rdfxml"),
        "versions": ("2.3", "2.2"),
    },
}
