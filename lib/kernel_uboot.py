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

from .utils import dbg, info, warn


def _get_kernel_dir(vgls):
    kdir = ""
    toolchain_dir = "toolchain-%s_gcc-%s_%s" % (
        vgls["config"]["config-target-arch-packages"],
        vgls["config"]["config-gcc-version"],
        vgls["config"]["config-libc"],
    )

    for dir in os.listdir(os.path.join(vgls["bdir"], "build_dir")):
        if dir.startswith(toolchain_dir):
            toolchain_dir = dir
            break
    toolchain_dir_path = os.path.join(vgls["bdir"], "build_dir", toolchain_dir)

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
    target_dir = "target-%s_%s" % (
        vgls["config"]["config-target-arch-packages"],
        vgls["config"]["config-libc"],
    )

    for dir in os.listdir(os.path.join(vgls["bdir"], "build_dir")):
        if dir.startswith(target_dir):
            target_dir = dir
            break
    target_dir_path = os.path.join(vgls["bdir"], "build_dir", target_dir)

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

    vgls["packages"]["linux"] = linux_dict
    return vgls


def get_uboot_info(vgls):
    uboot_dict = vgls["packages"]["uboot-envtools"]

    udir = _get_uboot_dir(vgls)

    if not udir:
        warn("U-Boot Config: U-Boot Build directory not defined.")
        return None

    if not os.path.exists(udir):
        warn("U-Boot Config: U-Boot Build directory does not exist.")
        warn("\tU-Boot build directory: %s" % udir)
        return None

    ver = _get_version_from_makefile(udir, with_extra=False)

    uboot_dict["cve_version"] = ver
    dbg("U-Boot Version: %s" % ver)
    uboot_dict["name"] = "uboot"
    uboot_dict["cve_product"] = "uboot"
    return vgls
