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

import os
import sys
import subprocess

from .utils import mkdirhier
from .utils import dbg, info, warn, err


def _get_toolchain_dir_name(vgls):
    makefile_dir = os.path.join(vgls['bdir'], "package", "kernel", "linux")
    try:
        my_env = os.environ.copy()
        my_env["TOPDIR"] = vgls["bdir"]
        mk_vals = subprocess.Popen(
            [
                "make",
                "--no-print-directory",
                "-C",
                makefile_dir,
                "val.TOOLCHAIN_DIR_NAME"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=my_env
        )
        out, _ = mk_vals.communicate()
        toolchain_dir = out.decode().strip().splitlines()
        return toolchain_dir[0]
    except Exception as _:
        dbg("Toolchain directory location not found.")
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
    # handle cases for some 64bit builds target directory name doesn't include 64
    target_dir_64 = "target-%s_%s_64_%s" % (
        vgls["config"]["config-arch"],
        vgls["config"]["config-cpu-type"],
        vgls["config"]["config-libc"],
    )
    target_dir = "target-%s_%s_%s" % (
        vgls["config"]["config-arch"],
        vgls["config"]["config-cpu-type"],
        vgls["config"]["config-libc"],
    )
    target_dirs = [target_dir_64, target_dir]

    build_dir = os.path.join(vgls.get("bdir"), "build_dir")
    if not os.path.exists(build_dir):
        err([
            "Invalid directory path: %s" % build_dir,
            "It seems you have not built Openwrt image yet.",
            "Build Openwrt image by running `make` inside Openwrt Build directory: %s" % vgls.get("bdir"),
            "and than try again."
             ])
        sys.exit(1)

    for dir in os.listdir(build_dir):
        if dir.startswith(target_dirs[0]) or dir.startswith(target_dirs[1]):
            target_dir = dir
            break
    target_dir_path = os.path.join(build_dir, target_dir)

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
    license_string = "unknown"
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


def get_kernel_info(vgls):
    linux_dict = vgls["packages"]["linux"]

    kdir = _get_kernel_dir(vgls)
    if not kdir:
        warn("Kernel Config: Kernel Build directory not found.")
        return None
    ver = _get_version_from_makefile(kdir)
    linux_dict["version"] = ver
    linux_dict["cve_version"] = ver
    dbg("Kernel Version: %s" % ver)

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
    uboot_dict["cpe_id"] = "unknown"
    uboot_dict["license"] = _get_license_from_makefile(udir)
    uboot_dict["cve_version"] = uboot_dict["version"] = ver
    dbg("U-Boot Version: %s" % ver)
    uboot_dict["name"] = uboot_dict["cve_product"] = uboot_dict["rawname"] = "u-boot"

    uconfig_out = "none"
    config_opts = _uboot_config(vgls, udir)
    if config_opts:
        uconfig_out = _write_config(vgls, uboot_dict, config_opts)
    if uconfig_out != "none":
        dbg("U-Boot Config: Wrote %d options to %s" % (len(config_opts), uconfig_out))
    vgls["uconfig"] = uconfig_out
    vgls["packages"]["u-boot"] = uboot_dict
    return vgls
