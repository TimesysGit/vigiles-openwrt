#!/usr/bin/env python3

###############################################################################
#
# vigiles-openwrt.py -- Timesys Vigiles utility for image manifest generation
# used for security monitoring and notification for OpenWrt.
#
# Copyright (C) 2021 Timesys Corporation
#
#
# This source is released under the MIT License.
#
#######################################################################################


"""
usage: vigiles-openwrt.py [-h] [-b BDIR] [-o ODIR] [-D] [-I] [-N MANIFEST_REPORT_NAME]
                          [-K LLKEY] [-C LLDASHBOARD]

Arguments:
  -h, --help                show this help message and exit
  -b BDIR, --build BDIR
                            OpenWrt Build Directory
  -o ODIR, --output ODIR
                            Vigiles Output Directory
  -D, --enable-debug        Enable Debug Output
  -I, --write-intermediate
                            Save Intermediate JSON Dictionaries
  -N  MANIFEST_REPORT_NAME, --name MANIFEST_REPORT_NAME
                            Custom Manifest/Report name
  -K  LLKEY, --keyfile LLKEY
                            Path of LinuxLink credentials file
  -C LLDASHBOARD, --dashboard-config LLDASHBOARD
                            Path of LinuxLink Dashboard Config file
"""
#######################################################################################


import argparse
import os
import sys
import json

from lib.openwrt import get_config_options
from lib.manifest import write_manifest
import lib.packages as packages
from lib.checkcves import vigiles_request
from lib.kernel_uboot import get_kernel_info, get_uboot_info

from lib.utils import set_debug
from lib.utils import dbg, err


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-b", "--build", required=True, dest="bdir", help="OpenWrt Build Directory"
    )
    parser.add_argument(
        "-o", "--output", required=True, dest="odir", help="Vigiles Output Directory"
    )
    parser.add_argument(
        "-D",
        "--enable-debug",
        dest="debug",
        help="Enable Debug Output",
        action="store_true",
    )
    parser.add_argument(
        "-I",
        "--write-intermediate",
        dest="write_intm",
        help="Save Intermediate JSON Dictionaries",
        action="store_true",
    )
    parser.add_argument(
        "-N",
        "--name",
        dest="manifest_name",
        help="Custom Manifest Name",
        default="",
    )
    parser.add_argument(
        "-K",
        "--keyfile",
        dest="llkey",
        help="Location of LinuxLink credentials file"
    )
    parser.add_argument(
        "-C",
        "--dashboard-config",
        dest="lldashboard",
        help="Location of LinuxLink Dashboard Config file",
    )
    args = parser.parse_args()

    set_debug(args.debug)

    vgls = {
        "write_intm": args.write_intm,
        "bdir": args.bdir.strip() if args.bdir else None,
        "odir": args.odir.strip() if args.odir else None,
        "manifest_name": args.manifest_name.strip(),
        "llkey": args.llkey.strip() if args.llkey else "",
        "lldashboard": args.lldashboard.strip() if args.lldashboard else "",
    }

    if not os.path.exists(vgls.get("bdir")):
        err("Invalid path for Openwrt Build directory")
        sys.exit(1)

    if not vgls.get("odir", None):
        vgls["odir"] = os.path.join(os.path.abspath, "vigiles-output")

    dbg("Vigiles OpenWrt Config: %s" % json.dumps(vgls, indent=4, sort_keys=True))
    return vgls


def collect_metadata(vgls):
    dbg("Getting Config Info ...")
    vgls["config"] = get_config_options(vgls)
    if not vgls["config"]:
        sys.exit(1)

    dbg("Getting Package List ...")
    vgls["packages"] = packages.get_package_info(vgls)

    if not vgls["packages"]:
        sys.exit(1)

    if "linux" in vgls["packages"]:
        dbg("Getting Kernel Info ...")
        get_kernel_info(vgls)

    if "uboot-envtools" in vgls["packages"]:
        dbg("Getting U-Boot Info ...")
        get_uboot_info(vgls)


def run_check(vgls):
    vgls_chk = {
        "keyfile": vgls.get("llkey", ""),
        "manifest": vgls.get("manifest", ""),
        "report": vgls.get("report", ""),
        "dashboard": vgls.get("lldashboard", ""),
    }
    vigiles_request(vgls_chk)


def __main__():
    vgls = parse_args()
    collect_metadata(vgls)
    write_manifest(vgls)
    run_check(vgls)


__main__()
