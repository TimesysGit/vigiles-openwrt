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
from copy import deepcopy

from .utils import write_intm_json
from .utils import kconfig_to_py
from .utils import dbg, info, warn, UNKNOWN, UNSET
from .utils import get_makefile_variables


EXCLUDE_PKGS = ["toolchain"]
PACKAGE_SUPPLIER = "Organization: OpenWrt ()"
AVAILABLE_PKGS = {}
TOOLCHAIN_PKGS = {}
ALIAS_PKG_MAP = {}


def _get_pkgs(path):
    pkgs = defaultdict()
    for root, dirs, files in os.walk(os.path.join(path, "package"), followlinks=True):
        for f in files:
            if not f.endswith("Makefile"):
                continue
            pkgname = kconfig_to_py(os.path.basename(root))
            pkgpath = os.path.join(root, f)
            if pkgname in EXCLUDE_PKGS:
                TOOLCHAIN_PKGS[pkgname] = {"makefile": pkgpath}
                continue
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
                warn(f'Unable to parse package version for {mk_info.get("PKG_NAME", "pkg")}: {exc}')
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
            ALIAS_PKG_MAP[subpkg] = pkg
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


# Patch management in openwrt https://openwrt.org/docs/guide-developer/overview
# https://openwrt.org/docs/guide-developer/overview#how_a_package_is_compiled
def _pkg_patches(vgls, pkg):
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


def get_available_pkgs(vgls):
    avail_pkgs = _get_pkgs(vgls["bdir"])
    avail_pkgs_info = _get_pkg_make_info(avail_pkgs, vgls["bdir"])
    AVAILABLE_PKGS.update(deepcopy(avail_pkgs_info))
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
                pkgs[pkg] = deepcopy(full_pkg_list[full_pkg_list[pkg].get("name")])
        return pkgs

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
        _pkg_patches(vgls, known_packages[name])
        known_packages[name]["rawname"] = name
        known_packages[name]["component_type"] = ["component"]

    dbg("Getting Toolchain Info ...")
    pkg_dict = get_toolchain_info(vgls, known_packages)

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
        "makefile": make_path,
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
        "makefile": make_path,
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
        pkg_dict[libc_package]["component_type"] = ["component"]
        dbg("%s version: %s" % (libc_info["name"], libc_info["version"]))

    libgcc_info = get_libgcc_info(vgls)
    if libgcc_info:
        pkg_dict["libgcc"] = libgcc_info
        pkg_dict["libgcc"]["component_type"] = ["component"]
        dbg("%s version: %s" % (libgcc_info["name"], libgcc_info["version"]))

    return pkg_dict


def add_checksum_to_pkg_info(pkg_info, checksum):
    if len(checksum) == 64:
        algorithm = "SHA256"
    elif len(checksum) == 32:
        algorithm = "MD5"
    else:
        dbg("Checksum value not supported for pkg: {}".format(pkg_info.get("name")))
        return

    pkg_info["checksums"].append({
        "algorithm": algorithm,
        "checksum_value": checksum
        })


def get_pkg_hash_from_make_cmd(pkg, mkvar_list, mkfile_dir, bdir, pkg_info):
    try:
        my_env = os.environ.copy()
        my_env["TOPDIR"] = bdir
        checksum = get_makefile_variables(
            mkfile_dir, my_env, mkvar_list
        )
        checksum = checksum[0]
    except Exception as exc:
        dbg(f'Unable to parse package checksum: {exc}')
        checksum = None

    if checksum:
        add_checksum_to_pkg_info(pkg_info, checksum)


def get_pkg_checksums(vgls):
    pkg_dict = vgls["packages"]
    no_makefiles = []
    for pkg, pkg_info in pkg_dict.items():
        pkg_info["checksums"] = []
        mkfile_path = pkg_info.get("makefile", "")
        if not mkfile_path:
            no_makefiles.append(pkg)
            continue

        if pkg == "linux":
            mkvar_list = ["val.LINUX_KERNEL_HASH"]
            linux_dir = os.path.dirname(mkfile_path)
            get_pkg_hash_from_make_cmd(pkg, mkvar_list, linux_dir, vgls["bdir"], pkg_info)
            continue

        if pkg == "u-boot":
            mkvar_list = ["val.PKG_MIRROR_HASH", "val.PKG_MIRROR_MD5SUM", "val.PKG_HASH"]
            uboot_dir = os.path.join(
                vgls.get("bdir"), 
                "package", 
                "boot", 
                "uboot-%s" % vgls["config"].get("config-target-board", "")
            )
            get_pkg_hash_from_make_cmd(pkg, mkvar_list, uboot_dir, vgls["bdir"], pkg_info)
            continue

        if os.path.exists(mkfile_path):
            with open(mkfile_path, "r") as f:
                mkfile = f.read()
                pattern = r"^ifeq.*PKG_VERSION.*{}.*\n\s*(PKG_HASH|PKG_MIRROR_HASH|PKG_MIRROR_MD5SUM)\s*:=\s*([a-f0-9]+)".format(
                    re.escape(pkg_info["version"])
                    )
                match = re.search(pattern, mkfile, re.MULTILINE)
                if match:
                    matches = [match]
                else:
                    pattern = r"(PKG_HASH|PKG_MIRROR_HASH|PKG_MIRROR_MD5SUM)\s*:=\s*([a-f0-9]+)"
                    matches = re.finditer(pattern, mkfile)

                for match in matches:
                    hash = match.group(2).strip()
                    add_checksum_to_pkg_info(pkg_info, hash)
    if no_makefiles:
        warn("Makefile not found for packages : {}".format(no_makefiles))

    # remove makefile path
    pkg_dict = _remove_makefile_from_pkg_data(pkg_dict)

    return pkg_dict


def add_dependencies(pkg, pkg_dict, bdir):
    def _parse_deps(dep_str):
        deps = re.findall(r"\b[a-z]+(?:[_/-][a-z]+)*\b", dep_str)
        parsed_deps = set()
        available_pkgs = AVAILABLE_PKGS.keys()
        for dep in deps:
            if dep not in available_pkgs:
                continue
            parsed_deps.add(dep)
        return sorted(list(parsed_deps))

    def _get_build_dependencies(pkg, mkfile):
        dep_str = re.search(r"\bPKG_BUILD_DEPENDS\b(.*)", mkfile)
        if dep_str:
            return _parse_deps(dep_str.group(0))
        return []
        
    def _get_runtime_dependencies(pkg, mkfile):
        pattern = r"(?s)\bdefine Package/{pkg}\b(?:(?!\bendef\b)(?!^$).)*DEPENDS(?:(?!\bdefine Package/{pkg}\b)(?!^$).)*\bendef\b".format(pkg=re.escape(pkg))
        block = re.search(pattern, mkfile)
        if block:
            dep_str = re.search(r"\bDEPENDS\b(.*)", block.group(0).replace("\\\n", ""))
            if dep_str:
                return _parse_deps(dep_str.group(0))
        return []

    def include_deps_as_pkgs(deps, component_type, pkg_dict):
        dependency_only_comment = {
            "build": "Dependency Only; This component was identified as a build dependency by Vigiles",
            "runtime": "Dependency Only; This component was identified as a runtime dependency by Vigiles",
            "build&runtime": "Dependency Only; This component was identified as a build and runtime dependency by Vigiles",
        }
        for dep in deps:
            if dep not in pkg_dict.keys():
                alias_pkg = ALIAS_PKG_MAP.get(dep, dep)
                pkg_info = AVAILABLE_PKGS.get(alias_pkg)
                if not pkg_info:
                    continue
                pkg_dict[dep] = deepcopy(pkg_info)
                pkg_dict[dep]["comment"] = dependency_only_comment[component_type]
                pkg_dict[dep]["component_type"] = [component_type]
                add_dependencies(dep, pkg_dict, bdir)
            else:
                component_type_list = pkg_dict[dep].get("component_type", [])
                if not component_type_list:
                    continue
                if component_type and component_type not in component_type_list:
                    pkg_dict[dep]["component_type"].append(component_type)
                    pkg_dict[dep]["component_type"].sort()
                if "component" not in component_type_list:
                    if "build" in component_type_list and "runtime" in component_type_list:
                        pkg_dict[dep]["comment"] = dependency_only_comment["build&runtime"]
                    elif "build" in component_type_list:
                        pkg_dict[dep]["comment"] = dependency_only_comment["build"]
                    elif "runtime" in component_type_list:
                        pkg_dict[dep]["comment"] = dependency_only_comment["runtime"]

    makefile = AVAILABLE_PKGS.get(pkg, {}).get("makefile", "")
    if not makefile:
        alias = ALIAS_PKG_MAP.get(pkg)
        makefile = AVAILABLE_PKGS.get(alias, {}).get("makefile", "")
    if os.path.exists(makefile):
        with open(makefile, "r") as file:
            mkfile = file.read()
            # runtime dependencies
            runtime_deps = _get_runtime_dependencies(pkg, mkfile)
            dbg("Runtime dependencies for %s: %s" % (pkg, runtime_deps))
            include_deps_as_pkgs(runtime_deps, "runtime", pkg_dict)
            
            # build dependencies
            build_deps = _get_build_dependencies(pkg, mkfile)
            dbg("Build dependencies for %s: %s" % (pkg, build_deps))
            include_deps_as_pkgs(build_deps, "build", pkg_dict)  
    else:
        warn("Unable to find makefile for %s" % pkg)
        runtime_deps = []
        build_deps = []

    pkg_dict[pkg].update({"dependencies": {
        "build": build_deps,
        "runtime": runtime_deps
    }})
    

def get_toolchain_pkgs(vgls):
    toolchain_pkgs_info = _get_pkg_make_info(TOOLCHAIN_PKGS, vgls["bdir"])
    AVAILABLE_PKGS.update(deepcopy(toolchain_pkgs_info))
     

def get_package_dependencies(vgls):
    get_toolchain_pkgs(vgls)
    pkg_dict = deepcopy(vgls["packages"])
    pkg_list = list(vgls["packages"].keys())
    for pkg in pkg_list:
        add_dependencies(pkg, pkg_dict, vgls["bdir"])
    
    for pkg, pkg_info in pkg_dict.items():
        _pkg_patches(vgls, pkg_info)
    
    vgls["packages"] = pkg_dict
