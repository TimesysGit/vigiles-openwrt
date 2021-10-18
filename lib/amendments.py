###########################################################################
#
# Copyright (C) 2021 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################################

import csv
import json
import os

from collections import defaultdict

from .utils import dbg, info, warn


def _get_addl_packages(extra_csv):
    if not extra_csv:
        return {}

    if not os.path.exists(extra_csv):
        warn("Skipping Non-Existent additional-package File: %s" % extra_csv)
        return {}

    additional = {
        "additional_licenses": defaultdict(str),
        "additional_packages": defaultdict(dict),
    }

    extra_rows = []
    try:
        with open(extra_csv) as csv_in:
            reader = csv.reader(csv_in)
            for row in reader:
                if not len(row):
                    continue
                if row[0].startswith("#"):
                    continue

                pkg = row[0].strip()
                if len(row) > 1:
                    ver = row[1].strip()
                else:
                    ver = ""
                if len(row) > 2:
                    license = row[2].strip()
                else:
                    license = "unknown"
                extra_rows.append([pkg, ver, license])
    except Exception as e:
        warn("Additional Packages: %s" % e)
        return {}

    if not extra_rows:
        return {}

    # Check for a CSV header of e.g. "package,version,license" and skip it
    header = extra_rows[0]
    if header[0].lower() == "product":
        extra_rows = extra_rows[1:]

    for row in extra_rows:
        pkg = row[0].replace(" ", "-")
        ver = row[1].replace(" ", ".")
        license = row[2]
        license_key = pkg + ver

        dbg(
            "Extra Package: %s, Version: %s, License: %s = %s"
            % (pkg, ver, license_key, license)
        )

        pkg_vers = set(additional["additional_packages"].get(pkg, []))
        pkg_vers.add(ver)

        additional["additional_packages"][pkg] = sorted(list(pkg_vers))
        additional["additional_licenses"][license_key] = license

    dbg("Adding Package Info: %s" % json.dumps(additional, indent=4, sort_keys=True))
    info("Adding Packages: %s" % list(additional["additional_licenses"].keys()))

    return additional


def amend_manifest(vgls, manifest):
    addl_pkgs = _get_addl_packages(vgls["addl"])
    if addl_pkgs:
        manifest.update(addl_pkgs)
