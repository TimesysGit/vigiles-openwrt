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

from .openwrt import get_openwrt_license
from .utils import dbg, info, warn, sanitize_openwrt_version, UNKNOWN


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
                    license = UNKNOWN
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


def _get_excld_packages(excld_csv):
    if not excld_csv:
        return []

    if not os.path.exists(excld_csv):
        warn("Skipping Non-Existent exclude-package File: %s" % excld_csv)
        return []

    dbg("Importing Excluded Packages from %s" % excld_csv)

    excld_pkgs = set()
    try:
        with open(excld_csv) as csv_in:
            reader = csv.reader(csv_in)
            for row in reader:
                if not len(row):
                    continue
                if row[0].startswith("#"):
                    continue

                pkg = row[0].strip().lower()
                excld_pkgs.add(pkg.replace(" ", "-"))
    except Exception as e:
        warn("exclude-packages: %s" % e)
        return []

    dbg("Requested packages to exclude: %s" % list(excld_pkgs))
    return list(excld_pkgs)


def _filter_excluded_packages(vgls_pkgs, excld_pkgs):
    if not excld_pkgs or not vgls_pkgs:
        return

    pkg_matches = list(
        set([k for k, v in vgls_pkgs.items() if v["name"] in excld_pkgs])
    )

    info("Vigiles: Excluding Packages: %s" % sorted(pkg_matches))
    for pkg_key in pkg_matches:
        vgls_pkgs.pop(pkg_key)


def _append_openwrt_package(vgls, manifest):
    ver = sanitize_openwrt_version(manifest["distro_version"])
    lic = get_openwrt_license(vgls)
    tmp = {"cpe_id": UNKNOWN,
           "cve_product": "openwrt",
           "cve_version": ver,
           "license": lic,
           "name": "openwrt",
           "patches": [],
           "rawname": "openwrt",
           "download_location": UNKNOWN,
           "download_protocol": UNKNOWN,
           "version": ver}
    manifest["packages"]["openwrt"] = tmp


def _get_user_whitelist(whtlst_csv):
    if not whtlst_csv:
        return []

    if not os.path.exists(whtlst_csv):
        warn("Skipping Non-Existent CVE Whitelist File: %s" % whtlst_csv)
        return []

    dbg("Importing Whitelisted CVEs from %s" % whtlst_csv)

    whtlst_cves = set()
    try:
        with open(whtlst_csv) as csv_in:
            reader = csv.reader(csv_in)
            for row in reader:
                if not len(row):
                    continue
                if row[0].startswith('#'):
                    continue

                pkg = row[0].strip().upper()
                whtlst_cves.add(pkg.replace(' ', '-'))
    except Exception as e:
        warn("whitelist-cves: %s" % e)
        return []

    dbg("Requested CVEs to Ignore: %s" % list(whtlst_cves))
    return whtlst_cves


def _get_package_whitelist(pkg_dict):
    whitelist = set()
    for pdict in pkg_dict.values():
        wl = [
            cve
            for cve in pdict.get('ignore_cves', '').split(' ')
            if cve
        ]
        whitelist.update(wl)
    return whitelist


def _build_whitelist(vgls, manifest):
    whtlst = set()
    whtlst.update(_get_user_whitelist(vgls['whtlst']))
    whtlst.update(_get_package_whitelist(manifest['packages']))
    return list(whtlst)


def _expand_package_download_location(vgls, manifest):
    if vgls.get("kernel_mirrors") and vgls["kernel_mirrors"]:
        kernel_mirror = vgls["kernel_mirrors"][0]
        for package_info in manifest["packages"].values():
            if package_info.get("download_location") and "@KERNEL" in package_info.get("download_location"):
                tmp = package_info["download_location"]
                package_info["download_location"] = tmp.replace("@KERNEL", kernel_mirror)


def amend_manifest(vgls, manifest):
    addl_pkgs = _get_addl_packages(vgls["addl"])
    if addl_pkgs:
        manifest.update(addl_pkgs)

    excld_pkgs = _get_excld_packages(vgls["excld"])
    _filter_excluded_packages(manifest["packages"], excld_pkgs)
    _append_openwrt_package(vgls, manifest)
    _expand_package_download_location(vgls, manifest)

    whtlst_cves = _build_whitelist(vgls, manifest)
    if whtlst_cves:
        dbg("Ignoring CVEs: %s" %
            json.dumps(whtlst_cves, indent=4, sort_keys=True))
        manifest['whitelist'] = sorted(whtlst_cves)
