###########################################################################
#
# lib/packages.py - Helpers for parsing OpenWrt package metadata
#
# Copyright (C) 2021 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################################

import fnmatch
import json
import os
import re

from collections import defaultdict

from .utils import write_intm_json
from .utils import kconfig_to_py
from .utils import dbg, info, warn, UNKNOWN, UNSET
from .utils import get_makefile_variables


EXCLUDE_PKGS = ["toolchain"]
PACKAGE_SUPPLIER = "Organization: OpenWrt ()"


def _get_pkgs(path):
    pkgs = defaultdict()
    for root, dirs, files in os.walk(os.path.join(path, "package"), followlinks=True):
        for f in files:
            if not f.endswith("Makefile"):
                continue
            pkgname = kconfig_to_py(os.path.basename(root))
            if pkgname in EXCLUDE_PKGS:
                continue
            pkgpath = os.path.join(root, f)
            pkgs[pkgname] = {"makefile": pkgpath}
    return pkgs


shaver_string = "-[0-9A-Fa-f]{8}"
shaver_straight = re.compile("%s" % shaver_string)


def _sanitize_version(version_in):
    sha_match = shaver_straight.search(version_in)
    version_out = (
        version_in
        if not sha_match or "git" in version_in
        else version_in.replace(sha_match.group(), "")
    )

    if "-stable" in version_out:
        version_out = version_in.replace("-stable", "")

    if version_out != version_in:
        info("CVE Version Fixed Up: %s -> %s" % (version_in, version_out))
    return version_out


def _get_pkg_version(mk_info, bdir, makefile_dir):
    version = UNSET
    if "PKG_VERSION" in mk_info.keys() and mk_info["PKG_VERSION"]:
        if "$" in mk_info["PKG_VERSION"]:
            try:
                my_env = os.environ.copy()
                my_env["TOPDIR"] = bdir
                version = get_makefile_variables(
                    makefile_dir, my_env, ["val.PKG_VERSION"]
                )[0]
            except Exception as exc:
                dbg(f'Unable to parse package version: {exc}')
        else:
            version = mk_info["PKG_VERSION"]
    elif "PKG_UPSTREAM_VERSION" in mk_info.keys() and mk_info["PKG_UPSTREAM_VERSION"]:
        version = mk_info["PKG_UPSTREAM_VERSION"]
    version = _sanitize_version(version)
    if "PKG_SOURCE_VERSION" in mk_info.keys() and mk_info["PKG_SOURCE_VERSION"] \
        and "PKG_SOURCE_DATE" in mk_info.keys() and mk_info["PKG_SOURCE_DATE"]:
        version = mk_info["PKG_SOURCE_DATE"] + "-" + mk_info["PKG_SOURCE_VERSION"][:8]
    return version


def _get_pkg_license(mk_info):
    license = UNKNOWN
    if "SPDX-LICENSE-IDENTIFIER" in mk_info.keys():
        license = mk_info["SPDX-LICENSE-IDENTIFIER"]
    elif "PKG_LICENSE" in mk_info.keys():
        license = mk_info["PKG_LICENSE"]
    license = ",".join(license.split(" "))
    return license


def _get_pkg_cpe_id(mk_info):
    cpe_id = UNKNOWN
    if "PKG_CPE_ID" in mk_info.keys():
        cpe_id = mk_info["PKG_CPE_ID"]
    return cpe_id


def _get_pkg_cve_product(pkg, mk_info):
    if "PKG_CPE_ID" in mk_info.keys():
        cve_product = mk_info["PKG_CPE_ID"].strip().split(":")[-1]
    else:
        cve_product = pkg
    return cve_product


def _get_pkg_dwld_proto(mk_info):
    source_proto = UNKNOWN
    if "PKG_SOURCE_PROTO" in mk_info.keys():
        source_proto = mk_info["PKG_SOURCE_PROTO"].strip()
    return source_proto


def _get_pkg_cve_version(mk_info, bdir, makefile_dir):
    if "PKG_CVE_VERSION" in mk_info.keys():
        cve_version = mk_info["PKG_CVE_VERSION"]
    elif "PKG_RELEASE_VERSION" in mk_info.keys() and "$" not in mk_info["PKG_RELEASE_VERSION"]:
        cve_version = mk_info["PKG_RELEASE_VERSION"]
    else:
        cve_version = _get_pkg_version(mk_info, bdir, makefile_dir)
    return cve_version


def _get_download_location(pkgs, bdir):
    for pkg, pkginfo in pkgs.items():
        pkginfo["download_location"] = UNKNOWN
        if "makefile" in pkginfo.keys():
            makefile_dir = os.path.dirname(pkginfo["makefile"])
            try:
                my_env = os.environ.copy()
                my_env["TOPDIR"] = bdir
                pkg_source, pkg_url = get_makefile_variables(makefile_dir, my_env, ["val.PKG_SOURCE", "val.PKG_SOURCE_URL"])
                # select the first pkg source url
                pkg_url = pkg_url.split(" ")[0]
                if pkginfo["download_protocol"] == "git" or pkg_url.endswith("?"):
                    pkginfo["download_location"] = pkg_url
                else:
                    pkginfo["download_location"] = "%s/%s" % (pkg_url, pkg_source)
            except Exception as e:
                pkginfo["download_location"] = UNKNOWN
    return pkgs


def _get_pkg_make_info(pkgs, bdir):
    alias_pkgs = defaultdict()
    for pkg in pkgs:
        makefile = pkgs[pkg]["makefile"]
        makefile_dir = os.path.dirname(makefile)
        subpkgs = []
        with open(makefile) as mk:
            mk_info = {}
            for l in mk.readlines():
                if l.startswith("define Package") and len(l.strip().split("/")) == 2:
                    sub_pkg = l.split("/")[-1].strip()
                    if "$(PKG_NAME)" in sub_pkg:
                        sub_pkg = sub_pkg.replace("$(PKG_NAME)", pkg)
                    subpkgs.append(sub_pkg)
                    continue
                if ":=" in l:
                    k, v = l.strip().split(":=")[:2]
                    mk_info[k] = v
                elif "=" in l and "+=" not in l:
                    k, v = l.strip().split("=")[:2]
                    mk_info[k] = v
                elif "SPDX-License-Identifier" in l:
                    l = (
                        l.replace("#", "")
                        .replace("//*", "")
                        .replace("////", "")
                        .strip()
                    )
                    l_split = l.split(":")
                    mk_info[l_split[0].strip().upper()] = l_split[1].strip()
        pkgs[pkg]["name"] = pkg
        pkgs[pkg]["rawname"] = pkgs[pkg].get("name")
        pkgs[pkg]["version"] = _get_pkg_version(mk_info, bdir, makefile_dir)
        pkgs[pkg]["license"] = _get_pkg_license(mk_info)
        pkgs[pkg]["cpe_id"] = _get_pkg_cpe_id(mk_info)
        pkgs[pkg]["cve_product"] = _get_pkg_cve_product(pkg, mk_info)
        pkgs[pkg]["cve_version"] = _get_pkg_cve_version(mk_info, bdir, makefile_dir)
        pkgs[pkg]["package_supplier"] = PACKAGE_SUPPLIER
        pkgs[pkg]["download_protocol"] = _get_pkg_dwld_proto(mk_info)

        for subpkg in subpkgs:
            if subpkg != pkgs[pkg].get("name"):
                alias_pkgs[subpkg] = {}
                alias_pkgs[subpkg]["rawname"] = subpkg
                alias_pkgs[subpkg]["name"] = pkgs[pkg].get("name")
                alias_pkgs[subpkg]["version"] = pkgs[pkg].get("version")
                alias_pkgs[subpkg]["license"] = pkgs[pkg].get("license")
                alias_pkgs[subpkg]["cpe_id"] = pkgs[pkg].get("cpe_id")
                alias_pkgs[subpkg]["cve_product"] = pkgs[pkg].get("cve_product")
                alias_pkgs[subpkg]["cve_version"] = pkgs[pkg].get("cve_version")
                alias_pkgs[subpkg]["package_supplier"] = PACKAGE_SUPPLIER
                alias_pkgs[subpkg]["download_protocol"] = pkgs[pkg].get("download_protocol")
    pkgs.update(alias_pkgs)
    return pkgs


def _remove_makefile_from_pkg_data(pkg_dict):
    for pkg in pkg_dict:
        if "makefile" in pkg_dict[pkg]:
            del pkg_dict[pkg]["makefile"]
    return pkg_dict


def _patched_cves(src_patches, vgls):
    patched_dict = dict()

    cve_match = re.compile("CVE\-\d{4}\-\d+")

    # Matches last CVE-1234-211432 in the file name, also if written
    # with small letters. Not supporting multiple CVE id's in a single
    # file name.
    cve_file_name_match = re.compile(".*([Cc][Vv][Ee]\-\d{4}\-\d+)")

    for patch_path in src_patches:
        found_cves = list()

        patch_name = os.path.basename(patch_path)
        # Check patch file name for CVE ID
        fname_match = cve_file_name_match.search(patch_name)
        if fname_match:
            cve = fname_match.group(1).upper()
            found_cves.append(cve)

        with open(patch_path, "r", encoding="utf-8") as f:
            try:
                patch_text = f.read()
            except UnicodeDecodeError:
                info(
                    vgls,
                    "Failed to read patch %s using UTF-8 encoding"
                    " trying with iso8859-1" % patch_path,
                )
                f.close()
                with open(patch_path, "r", encoding="iso8859-1") as f:
                    patch_text = f.read()

        # Search for one or more "CVE-XXXX-XXXX+" lines
        for match in cve_match.finditer(patch_text):
            found_cves.append(match.group())

        if len(found_cves):
            dbg("Patches: Found CVEs for Someone: %s" % json.dumps(found_cves))

        for cve in found_cves:
            entry = patched_dict.get(cve, list())
            if patch_name not in entry:
                entry.append(patch_name)
            patched_dict.update({cve: entry})

    if len(patched_dict.keys()):
        dbg("Patches: Patched CVEs for Someone: %s" % json.dumps(patched_dict))

    return {key: sorted(patched_dict[key]) for key in sorted(patched_dict.keys())}


def get_available_pkgs(vgls):
    avail_pkgs = _get_pkgs(vgls["bdir"])
    avail_pkgs_info = _get_pkg_make_info(avail_pkgs, vgls["bdir"])
    return avail_pkgs_info


def get_package_info(vgls):
    config_dict = vgls.get("config", {})

    def _config_packages(config_dict):
        config_pkgs = set()

        for key, value in config_dict.items():
            if value is not True:
                continue

            if key.startswith("config-package-"):
                if not key.endswith("-supports"):
                    pkg = key[15:]
                    config_pkgs.add(pkg)

        dbg(
            "OpenWrt Config: %d possible packages (including firmware)"
            % len(config_pkgs)
        )
        return sorted(list(config_pkgs))

    def _known_packages(pkg_list):
        full_pkg_list = get_available_pkgs(vgls)
        pkg_rawname_list = [full_pkg_list[x]["rawname"] for x in full_pkg_list]
        pkgs = defaultdict()
        for pkg in pkg_list:
            if pkg in pkg_rawname_list:
                pkgs[pkg] = full_pkg_list[full_pkg_list[pkg].get("name")]
        return pkgs

    # Patch management in openwrt https://openwrt.org/docs/guide-developer/overview
    # https://openwrt.org/docs/guide-developer/overview#how_a_package_is_compiled
    def _pkg_patches(pkg):
        makefile = pkg.get("makefile", "")
        patch_list = []

        if not makefile:
            return

        makedir = os.path.dirname(makefile)
        if os.path.exists(os.path.join(makedir, "patches")):
            patch_list.extend(
                fnmatch.filter(
                    [p.path for p in os.scandir(os.path.join(makedir, "patches"))],
                    "*.patch",
                )
            )

        if patch_list:
            pkg["patches"] = sorted([os.path.basename(p) for p in patch_list])
            pkg["patched_cves"] = _patched_cves(patch_list, vgls)
            if pkg["patched_cves"]:
                dbg(
                    "Patched CVEs for %s" % pkg["name"],
                    [
                        "Total Patches: %d" % len(patch_list),
                        "Patch List: %s"
                        % json.dumps(patch_list, indent=12, sort_keys=True),
                        "CVEs: %s"
                        % json.dumps(pkg["patched_cves"], indent=12, sort_keys=True),
                    ],
                )

    # List of packages selected in .config
    config_pkg_list = _config_packages(config_dict)
    if not config_pkg_list:
        warn("No packages found in OpenWrt .config.")
        return None

    # Add kernel
    config_pkg_list.extend(["linux"])
    # Filter out known packages from build system
    known_packages = _known_packages(config_pkg_list)
    dbg("Found %d packages" % len(known_packages.keys()))

    if not known_packages:
        warn("No configured packages seem to exist in tree.")
        return None

    # populate source download locations of known packages
    _get_download_location(known_packages, vgls["bdir"])

    # Add patch info
    for name in known_packages.keys():
        _pkg_patches(known_packages[name])
        known_packages[name]["rawname"] = name

    dbg("Getting Toolchain Info ...")
    pkg_dict = get_toolchain_info(vgls, known_packages)

    # remove makefile path
    pkg_dict = _remove_makefile_from_pkg_data(pkg_dict)

    write_intm_json(vgls, "config-packages", pkg_dict)
    return pkg_dict


def get_libc_info(vgls):
    if not "config-libc" in vgls["config"]:
        return None, None
    libc_package = vgls["config"]["config-libc"]
    make_path = os.path.join(vgls["bdir"], "toolchain", libc_package, "common.mk")
    pkg_name, pkg_version, pkg_license, package_supplier = libc_package, UNSET, UNKNOWN, PACKAGE_SUPPLIER
    if os.path.exists(make_path):
        with open(make_path) as mk:
            mk_info = {}
            for l in mk.readlines():
                if l.startswith("PKG_NAME") and len(l.strip().split(":=")) == 2:
                    pkg_name = l.strip().split(":=")[-1]
                elif l.startswith("PKG_VERSION") and len(l.strip().split(":=")) == 2:
                    pkg_version = l.strip().split(":=")[-1]
                elif l.startswith("PKG_LICENSE") and len(l.strip().split(":=")) == 2:
                    pkg_license = l.strip().split(":=")[-1]
    if vgls["config"].get("config-%s-version" % pkg_name):
        pkg_version = vgls["config"].get("config-%s-version" % pkg_name)
    libc_info = {
        "name": libc_package,
        "rawname": libc_package,
        "version": pkg_version,
        "license": pkg_license,
        "cve_product": libc_package,
        "cve_version": pkg_version,
        "package_supplier": package_supplier,
        "download_location": UNKNOWN,
        "download_protocol": UNKNOWN,
    }

    patch_dir = os.path.join(vgls["bdir"], "toolchain", libc_package, "patches")
    if os.path.exists(patch_dir):
        patch_list = []
        patch_list.extend(
            fnmatch.filter(
                [p.path for p in os.scandir(patch_dir)],
                "*.patch",
            )
        )
        libc_info["patches"] = sorted([os.path.basename(p) for p in patch_list])
        libc_info["patched_cves"] = _patched_cves(patch_list, vgls)
    return libc_package, libc_info


def get_libgcc_info(vgls):
    if not "config-package-libgcc" in vgls["config"]:
        return None

    make_path = os.path.join(vgls["bdir"], "toolchain", "gcc", "common.mk")
    pkg_name, pkg_license, package_supplier = "gcc", UNKNOWN, PACKAGE_SUPPLIER
    if os.path.exists(make_path):
        with open(make_path) as mk:
            mk_info = {}
            for l in mk.readlines():
                if l.startswith("PKG_NAME") and len(l.strip().split(":=")) == 2:
                    pkg_name = l.strip().split(":=")[-1]
                elif l.startswith("PKG_LICENSE") and len(l.strip().split(":=")) == 2:
                    pkg_license = l.strip().split(":=")[-1]
    libgcc_info = {
        "name": pkg_name,
        "rawname": "libgcc",
        "version": vgls["config"].get("config-gcc-version"),
        "license": pkg_license,
        "cve_product": pkg_name,
        "cve_version": vgls["config"].get("config-gcc-version"),
        "package_supplier": package_supplier,
        "download_location": UNKNOWN,
        "download_protocol": UNKNOWN,
    }

    patch_dir = os.path.join(
        vgls["bdir"],
        "toolchain",
        "gcc",
        "patches",
        vgls["config"].get("config-gcc-version"),
    )
    if os.path.exists(patch_dir):
        patch_list = []
        patch_list.extend(
            fnmatch.filter(
                [p.path for p in os.scandir(patch_dir)],
                "*.patch",
            )
        )
        libgcc_info["patches"] = sorted([os.path.basename(p) for p in patch_list])
        libgcc_info["patched_cves"] = _patched_cves(patch_list, vgls)
    return libgcc_info


def get_toolchain_info(vgls, pkg_dict):
    libc_package, libc_info = get_libc_info(vgls)
    if libc_info:
        pkg_dict[libc_package] = libc_info
        dbg("%s version: %s" % (libc_info["name"], libc_info["version"]))

    libgcc_info = get_libgcc_info(vgls)
    if libgcc_info:
        pkg_dict["libgcc"] = libgcc_info
        dbg("%s version: %s" % (libgcc_info["name"], libgcc_info["version"]))

    return pkg_dict
