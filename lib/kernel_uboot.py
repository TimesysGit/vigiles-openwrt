###########################################################################
#
# lib/kernel_uboot.py - Helpers for parsing Kernel/U-Boot metadata
#
# Copyright (C) 2021 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################################

import fnmatch
import os
import re
import sys
import subprocess
from urllib.parse import urljoin

from .utils import mkdirhier
from .utils import dbg, info, warn, err, UNKNOWN
from .utils import get_makefile_variables
from .packages import _patched_cves


def _get_toolchain_dir_name(vgls):
    board = vgls["config"].get("config-target-board", "")
    makefile_dir = os.path.join(vgls['bdir'], "target", "linux", board)
    try:
        my_env = os.environ.copy()
        my_env["TOPDIR"] = vgls["bdir"]
        toolchain_dir = get_makefile_variables(makefile_dir, my_env, ["val.TOOLCHAIN_DIR_NAME"])
        return toolchain_dir[0]
    except Exception as _:
        dbg("Toolchain directory location not found.")
    return "InvalidPath"


def _get_target_dir_name(vgls):
    board = vgls["config"].get("config-target-board", "")
    makefile_dir = os.path.join(vgls['bdir'], "target", "linux", board)
    try:
        my_env = os.environ.copy()
        my_env["TOPDIR"] = vgls["bdir"]
        target_dir = get_makefile_variables(makefile_dir, my_env, ["val.TARGET_DIR_NAME"])
        return target_dir[0]
    except Exception as _:
        dbg("Target directory location not found.")
    return "InvalidPath"


def _get_kernel_dir(vgls):
    kdir = ""
    build_dir = os.path.join(vgls.get("bdir"), "build_dir")
    if not os.path.exists(build_dir):
        err([
            "Invalid directory path: %s" % build_dir,
            "It seems you have not built Openwrt image yet.",
            "Build Openwrt image by running `make` inside Openwrt Build directory: %s" % vgls.get("bdir"),
            "and than try again."
             ])
        sys.exit(1)

    toolchain_dir_name = _get_toolchain_dir_name(vgls)
    toolchain_dir_path = os.path.join(build_dir, toolchain_dir_name)
    if not os.path.exists(toolchain_dir_path):
        return ""

    if "linux" in os.listdir(toolchain_dir_path):
        if os.path.islink(os.path.join(toolchain_dir_path, "linux")):
            kdir = os.readlink(os.path.join(toolchain_dir_path, "linux"))
            kdir = os.path.join(toolchain_dir_path, kdir)
        else:
            kdir = os.path.join(toolchain_dir_path, "linux")
    return kdir


def _get_uboot_dir(vgls):
    udir = ""
    build_dir = os.path.join(vgls.get("bdir"), "build_dir")
    if not os.path.exists(build_dir):
        err([
            "Invalid directory path: %s" % build_dir,
            "It seems you have not built Openwrt image yet.",
            "Build Openwrt image by running `make` inside Openwrt Build directory: %s" % vgls.get("bdir"),
            "and than try again."
             ])
        sys.exit(1)

    target_dir_name = _get_target_dir_name(vgls)
    target_dir_path = os.path.join(build_dir, target_dir_name)

    if not os.path.exists(target_dir_path):
        return ""

    stop_flag = False
    for root, dirs, files in os.walk(target_dir_path, followlinks=True):
        if stop_flag:
            break
        if not os.path.basename(root).startswith("u-boot"):
            continue
        for f in files:
            if not f.endswith("Makefile"):
                continue
            udir = root
            stop_flag = True
            break
    return udir


def _get_version_from_makefile(target_path, with_extra=True):
    v = {"major": None, "minor": None, "revision": None, "extra": None}
    version_string = None
    makefile_path = os.path.join(target_path, "Makefile")
    if not os.path.exists(makefile_path):
        warn("Source directory not found: %s." % makefile_path)
        return None

    try:
        with open(makefile_path) as f_in:
            for line in f_in:
                _split = line.split("=")
                if len(_split) != 2:
                    continue
                key, val = [x.strip() for x in _split]
                if key == "VERSION":
                    v["major"] = val
                elif key == "PATCHLEVEL":
                    v["minor"] = val
                elif key == "SUBLEVEL":
                    v["revision"] = val
                elif key == "EXTRAVERSION":
                    v["extra"] = val
            f_in.close()
    except Exception as e:
        warn(
            "Versions: Could not read/parse Makefile.",
            ["Path: %s." % makefile_path, "Error: %s" % e],
        )
        return None

    if v["major"] and v["minor"]:
        version_string = ".".join([v["major"], v["minor"]])
    if v["revision"]:
        version_string = ".".join([version_string, v["revision"]])
    if v["extra"] and with_extra:
        version_string = version_string + v["extra"]
    return version_string


def _get_license_from_makefile(target_path):
    license_string = UNKNOWN
    makefile_path = os.path.join(target_path, "Makefile")
    if not os.path.exists(makefile_path):
        warn("Source directory not found: %s." % makefile_path)
        return license_string
    with open(makefile_path) as mk:
        for l in mk.readlines():
            if "SPDX-License-Identifier" in l:
                l = (
                    l.replace("#", "")
                        .replace("//*", "")
                        .replace("////", "")
                        .strip()
                )
                l_split = l.split(":")
                license_string = l_split[1].strip()
    license_string = ",".join(license_string.split(" "))
    return license_string


def _get_config_opts(config_file, preamble_length=0):
    config_preamble = []
    config_set = set()
    config_options = list()

    if not os.path.exists(config_file):
        warn("Config File Not Found: %s" % config_file)
        return None

    try:
        with open(config_file, "r") as config_in:
            f_data = [f_line.rstrip() for f_line in config_in]
            if preamble_length:
                config_preamble = f_data[:preamble_length]
                f_data = f_data[preamble_length + 1 :]
            config_set.update(
                [
                    f_line
                    for f_line in f_data
                    if f_line.startswith("CONFIG_") and f_line.endswith(("=y", "=m"))
                ]
            )
    except Exception as e:
        warn("Config: Could not read/parse %s." % config_file)
        warn("\tError: %s" % e)
        return None
    config_options = config_preamble + sorted(list(config_set))
    return config_options


def _kernel_config(vgls, kdir):
    kconfig_in = vgls["kconfig"]

    if not kconfig_in or kconfig_in == "none":
        return None

    if kconfig_in == "auto":
        dot_config = os.path.relpath(os.path.join(kdir, ".config"))
    else:
        dot_config = kconfig_in

    if not os.path.exists(dot_config):
        warn(
            "Kernel .config file does not exist.",
            ["File: %s" % kconfig_in, "Kernel .config filtering will be disabled."],
        )
        return None

    info("Kernel Config: Using %s" % dot_config)

    config_options = []
    dot_config_options = _get_config_opts(dot_config, preamble_length=4)

    if dot_config_options:
        config_options.extend(dot_config_options)
        dbg("Kernel Config: %d Options" % len(config_options))
    return config_options


def _get_kernel_major_minor(ver):
    return ".".join(ver.split(".")[:2])


# Kernel Patch mgmt. in OpenWrt
# https://openwrt.org/docs/guide-developer/toolchain/use-patches-with-buildsystem#adding_or_editing_kernel_patches
def _get_kernel_patches(vgls, ver):
    patches = []
    patched_cves = {}
    linux_dir = os.path.join(vgls.get("bdir"), "target", "linux")
    generic_dir = os.path.join(linux_dir, "generic")
    board_dir = os.path.join(linux_dir, vgls["config"].get("config-target-board", "openwrt"))
    kernel_version = _get_kernel_major_minor(ver)
    board_patch_dirs = ["patches-%s" % kernel_version]
    generic_patch_dirs = ["backport-%s" % kernel_version,
                          "pending-%s" % kernel_version,
                          "hack-%s" % kernel_version,
                          "patches-%s" % kernel_version]

    def _get_patches(tdir, patch_dirs):
        if os.path.exists(tdir):
            for dir in os.listdir(tdir):
                if dir in patch_dirs and os.path.isdir(os.path.join(tdir, dir)):
                    patch_dir = os.path.join(tdir, dir)
                    patch_list = []
                    patch_list.extend(
                        fnmatch.filter(
                            [p.path for p in os.scandir(patch_dir)],
                            "*.patch",
                        )
                    )
                    patches.extend(sorted([os.path.basename(p) for p in patch_list]))
                    patched_cves.update(_patched_cves(patch_list, vgls))

    _get_patches(generic_dir, generic_patch_dirs)
    _get_patches(board_dir, board_patch_dirs)
    return patches, patched_cves


def _uboot_config(vgls, udir):
    uconfig_in = vgls["uconfig"]

    if not uconfig_in or uconfig_in == "none":
        return None

    if uconfig_in == "auto":
        dot_config = os.path.relpath(os.path.join(udir, ".config"))
        autoconf = os.path.relpath(os.path.join(udir, "include", "autoconf.mk"))
    else:
        dot_config = uconfig_in
        autoconf = ""
    if not os.path.exists(dot_config):
        warn("U-Boot .config file does not exist.")
        warn("\tFile: %s" % uconfig_in)
        warn("\tU-Boot .config filtering will be disabled.")
        return None

    info("U-Boot Config: Using %s %s" % (dot_config, autoconf))

    config_options = []
    dot_config_options = _get_config_opts(dot_config, preamble_length=4)
    if dot_config_options:
        config_options.extend(dot_config_options)
        dbg("U-Boot Config: %d .config Options" % len(dot_config_options))

    if autoconf and os.path.exists(autoconf):
        autoconf_options = _get_config_opts(autoconf)
        if autoconf_options:
            config_options.extend(autoconf_options)
            dbg("U-Boot Config: %d autoconf Options" % len(autoconf_options))

    return config_options


def _get_uboot_patches(vgls):
    patches = []
    patched_cves = {}
    uboot_dir = os.path.join(vgls.get("bdir"), "package", "boot", "uboot-%s" % vgls["config"].get("config-target-board", ""))

    if os.path.exists(uboot_dir):
        for dir in os.listdir(uboot_dir):
            if dir == "patches" and os.path.isdir(os.path.join(uboot_dir, dir)):
                patch_dir = os.path.join(uboot_dir, dir)
                patch_list = []
                patch_list.extend(
                    fnmatch.filter(
                        [p.path for p in os.scandir(patch_dir)],
                        "*.patch",
                    )
                )
                patches.extend(sorted([os.path.basename(p) for p in patch_list]))
                patched_cves.update(_patched_cves(patch_list, vgls))
    return patches, patched_cves


def _write_config(vgls, pkg_dict, config_options):
    vgls_dir = vgls["odir"]
    _name = pkg_dict.get("name")
    _ver = pkg_dict.get("cve_version")
    _spec = "-".join([_name, _ver])
    _fname = ".".join([_spec, "config"])
    config_file = os.path.join(vgls_dir, _fname)

    if not config_options:
        return

    mkdirhier(vgls_dir)

    try:
        with open(config_file, "w") as config_out:
            print("\n".join(config_options), file=config_out, flush=True)
            print("\n", file=config_out, flush=True)
    except Exception as e:
        warn(
            "Could not write .config output.",
            [
                "File: %s" % config_file,
                "Error: %s" % e,
            ],
        )
        config_file = "none"
    return config_file


def _get_kernel_mirrors(vgls):
    download_script_path = os.path.join(vgls['bdir'], "scripts", "download.pl")
    kernel_mirrors = []
    try:
        with open(download_script_path) as dwld_file:
            content = dwld_file.readlines()
            kernel_start_flag = False
            mirror_start_flag = False
            for line in content:
                if "@KERNEL" in line:
                    kernel_start_flag = True
                elif kernel_start_flag and mirror_start_flag is False and "foreach" in line:
                    mirror_start_flag = True
                elif kernel_start_flag and mirror_start_flag and "@mirrors" in line:
                    tmp = line.strip().split(",")[-1].strip()
                    kernel_mirrors.append(tmp.replace('"', "").replace("/$dir;", ""))
                elif kernel_start_flag and mirror_start_flag and "}" in line:
                    break
    except Exception as _:
        dbg("Kernel mirrors not found.")
    vgls["kernel_mirrors"] = kernel_mirrors
    return kernel_mirrors


def _get_kernel_major(ver):
    return ver.split(".")[0]


def _adjust_linux_site(linux_site, ver):
    if not re.search(r'\d', linux_site):
        linux_site = linux_site.replace("v.x", "v%s.x" % _get_kernel_major(ver))
    return linux_site


def _adjust_linux_source(linux_source, ver):
    # populate kernel version in source package name if not already present
    if not re.search(r'\d', linux_source):
        linux_source = ".".join(
            [linux_source.split(".")[0] + _get_kernel_major_minor(ver)] + linux_source.split(".")[1:])
    return linux_source


def _get_kernel_patchversion(config):
    patchver_list = [
        k.replace("config-linux-", "").replace("-", ".")
        for k, v in config.items()
        if v is True and k.startswith('config-linux')
    ]
    return patchver_list[0] if patchver_list else None


def _get_kernel_download_location(vgls, ver):
    if vgls["config"]["config-kernel-git-clone-uri"]:
        return vgls["config"]["config-kernel-git-clone-uri"]

    makefile_dir = os.path.join(vgls['bdir'], "package", "kernel", "linux")
    make_override_vars = None
    try:
        kernel_patchver = _get_kernel_patchversion(vgls['config'])
        if kernel_patchver:
            make_override_vars = "KERNEL_PATCHVER=%s" % kernel_patchver
    except Exception as _:
        dbg("Kernel patch version not found in .config file")

    try:
        kernel_mirrors = _get_kernel_mirrors(vgls)
        my_env = os.environ.copy()
        my_env["TOPDIR"] = vgls["bdir"]
        linux_site, linux_source = get_makefile_variables(makefile_dir, my_env, ["val.LINUX_SITE", "val.LINUX_SOURCE"], make_override_vars)
        linux_site = _adjust_linux_site(linux_site, ver)
        linux_source = _adjust_linux_source(linux_source, ver)

        # pick first kernel mirror and make kernel download url
        if kernel_mirrors:
            linux_site = linux_site.replace("@KERNEL", kernel_mirrors[0])
        return "%s/%s" % (linux_site, linux_source)
    except Exception as _:
        dbg("Kernel download location not found.")
    return UNKNOWN


def _get_uboot_download_location(vgls):
    board = vgls["config"].get("config-target-board", "")
    board_uboot_dir = os.path.join(vgls['bdir'], "package", "boot", "uboot-%s" % board)
    if not os.path.exists(board_uboot_dir):
        dbg("U-boot download location not found.")
        return UNKNOWN

    try:
        my_env = os.environ.copy()
        my_env["TOPDIR"] = vgls["bdir"]
        pkg_source, pkg_source_url = get_makefile_variables(board_uboot_dir, my_env, ["val.PKG_SOURCE", "val.PKG_SOURCE_URL"])
        pkg_source_urls = pkg_source_url.split(" ")
        # pick first source url and make package download url
        return urljoin(pkg_source_urls[0], pkg_source)
    except Exception as _:
        dbg("U-boot download location not found.")
    return UNKNOWN


def get_kernel_info(vgls):
    linux_dict = vgls["packages"]["linux"]

    kdir = _get_kernel_dir(vgls)
    if not kdir:
        warn("Kernel Config: Kernel Build directory not found.")
        return None
    ver = _get_version_from_makefile(kdir)
    linux_dict["version"] = ver
    linux_dict["cve_version"] = ver
    linux_dict["download_location"] = _get_kernel_download_location(vgls, ver)
    linux_dict["download_protocol"] = UNKNOWN
    dbg("Kernel Version: %s" % ver)
    linux_dict["patches"], linux_dict["patched_cves"] = _get_kernel_patches(vgls, ver)

    kconfig_out = "none"
    config_opts = _kernel_config(vgls, kdir)
    if config_opts:
        kconfig_out = _write_config(vgls, linux_dict, config_opts)
    if kconfig_out != "none":
        dbg("Kernel Config: Wrote %d options to %s" % (len(config_opts), kconfig_out))
    vgls["kconfig"] = kconfig_out
    vgls["packages"]["linux"] = linux_dict
    return vgls


def get_uboot_info(vgls):
    uboot_dict = {}

    udir = _get_uboot_dir(vgls)

    if not udir:
        warn("U-Boot Config: U-Boot Build directory not defined.")
        return None

    if not os.path.exists(udir):
        warn("U-Boot Config: U-Boot Build directory does not exist.")
        warn("\tU-Boot build directory: %s" % udir)
        return None

    ver = _get_version_from_makefile(udir, with_extra=False)
    uboot_dict["cpe_id"] = UNKNOWN
    uboot_dict["license"] = _get_license_from_makefile(udir)
    uboot_dict["cve_version"] = uboot_dict["version"] = ver
    dbg("U-Boot Version: %s" % ver)
    uboot_dict["name"] = uboot_dict["cve_product"] = uboot_dict["rawname"] = "u-boot"
    uboot_dict["download_location"] = _get_uboot_download_location(vgls)
    uboot_dict["download_protocol"] = UNKNOWN
    uboot_dict["patches"], uboot_dict["patched_cves"] = _get_uboot_patches(vgls)

    uconfig_out = "none"
    config_opts = _uboot_config(vgls, udir)
    if config_opts:
        uconfig_out = _write_config(vgls, uboot_dict, config_opts)
    if uconfig_out != "none":
        dbg("U-Boot Config: Wrote %d options to %s" % (len(config_opts), uconfig_out))
    vgls["uconfig"] = uconfig_out
    vgls["packages"]["u-boot"] = uboot_dict
    return vgls
