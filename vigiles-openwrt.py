#!/usr/bin/env python3

###############################################################################
#
# vigiles-openwrt.py -- Vigiles utility for SBOM generation
# used for vulnerability monitoring and notification for OpenWrt.
#
# Copyright (C) 2021 Timesys Corporation
# Copyright (C) 2025 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
#######################################################################################


"""
usage: vigiles-openwrt.py [-h] -b BDIR [-o ODIR] [-D] [-I] [-N MANIFEST_NAME] [-K LLKEY] [-C LLDASHBOARD] [-U] [-M] [-k KCONFIG] [-u UCONFIG] [-A ADDL] [-E EXCLD] [-W WHTLST] [-F SUBFOLDER_NAME]
                          [-e ECOSYSTEMS] [-s SUBSCRIBE] [--kernel-source KDIR] [--uboot-source UDIR] [--download-sbom] [--vigiles-bin VIGILES_BIN] [--download-sbom-format {cyclonedx,spdx,spdx-lite}]
                          [--download-sbom-version DOWNLOAD_SBOM_VERSION] [--download-sbom-file-type DOWNLOAD_SBOM_FILE_TYPE] [--queue-jobs] [--timeout TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  -b BDIR, --build BDIR
                        OpenWrt Build Directory
  -o ODIR, --output ODIR
                        Vigiles Output Directory
  -D, --enable-debug    Enable Debug Output
  -I, --write-intermediate
                        Save Intermediate JSON Dictionaries
  -N MANIFEST_NAME, --name MANIFEST_NAME
                        Custom Manifest Name
  -K LLKEY, --keyfile LLKEY
                        Location of Vigiles API key file
  -C LLDASHBOARD, --dashboard-config LLDASHBOARD
                        Location of Vigiles Dashboard Config file
  -U, --upload-only     Upload the manifest only; do not wait for report.
  -M, --metadata-only   Only collect metadata, don't run online Check
  -k KCONFIG, --kernel-config KCONFIG
                        Custom Kernel Config to Use
  -u UCONFIG, --uboot-config UCONFIG
                        Custom U-Boot Config(s) to Use
  -A ADDL, --additional-packages ADDL
                        File of Additional Packages to Include
  -E EXCLD, --exclude-packages EXCLD
                        File of Packages to Exclude
  -W WHTLST, --whitelist-cves WHTLST
                        File of CVEs to Ignore/Whitelist
  -F SUBFOLDER_NAME, --subfolder SUBFOLDER_NAME
                        Name of subfolder to upload to
  -e ECOSYSTEMS, --ecosystems ECOSYSTEMS
                        Comma separated string of ecosystems that should be used for generating reports
  -s SUBSCRIBE, --subscribe SUBSCRIBE
                        Set subscription frequency for sbom report notifications: "none", "daily", "weekly", "monthly"
  --kernel-source KDIR  Location of custom kernel source directory
  --uboot-source UDIR   Location of custom uboot source directory
  --download-sbom       Download Converted SBOM (CycloneDX/SPDX)
  --vigiles-bin VIGILES_BIN
                        Path to vigiles CLI binary
  --download-sbom-format {cyclonedx,spdx,spdx-lite}
                        SBOM format to download
  --download-sbom-version DOWNLOAD_SBOM_VERSION
                        SBOM version to download
  --download-sbom-file-type DOWNLOAD_SBOM_FILE_TYPE
                        SBOM file type to download
  --queue-jobs          Submit jobs and exit immediately without waiting for results.
  --timeout TIMEOUT     Maximum number of seconds to wait for a background job (default: 600)
"""
#######################################################################################


import argparse
import os
import sys
import json

from lib.openwrt import get_config_options
from lib.manifest import write_manifest, VIGILES_OUTPUT_DIR
import lib.packages as packages
from lib.checkcves import vigiles_request
from lib.clitasks import validate_download_options, download_sbom
from lib.constants import DOWNLOAD_SBOM_FORMATS
from lib.kernel_uboot import get_kernel_info, get_uboot_info
from lib.jobs import DEFAULT_JOB_TIMEOUT

from lib.utils import set_debug
from lib.utils import dbg, err


def parse_args():
    def valid_config(config):
        if config.lower() in ["auto", "none"]:
            return config.lower().strip()
        config_path = os.path.abspath(config)
        if os.path.isfile(config_path):
            return config_path.strip()
        raise argparse.ArgumentTypeError("Invalid value for config %s. Acceptable values are 'auto', 'none' or a valid config file path" % config)

    def positive_int(value):
        try:
            value = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("must be a positive integer")
        if value < 1:
            raise argparse.ArgumentTypeError("must be a positive integer")
        return value

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-b",
        "--build",
        required=True,
        dest="bdir",
        help="OpenWrt Build Directory"
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="odir",
        help="Vigiles Output Directory"
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
        help="Location of Vigiles API key file"
    )
    parser.add_argument(
        "-C",
        "--dashboard-config",
        dest="lldashboard",
        help="Location of Vigiles Dashboard Config file",
    )
    parser.add_argument(
        "-U",
        "--upload-only",
        dest="upload_only",
        help="Upload the manifest only; do not wait for report.",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-M",
        "--metadata-only",
        dest="do_check",
        help="Only collect metadata, don\'t run online Check",
        action="store_false",
    )
    parser.add_argument(
        "-k",
        "--kernel-config",
        dest="kconfig",
        help="Custom Kernel Config to Use",
        default="auto",
        type=valid_config
    )
    parser.add_argument(
        "-u",
        "--uboot-config",
        dest="uconfig",
        help="Custom U-Boot Config(s) to Use",
        default="auto",
        type=valid_config
    )
    parser.add_argument(
        "-A",
        "--additional-packages",
        dest="addl",
        help="File of Additional Packages to Include",
    )
    parser.add_argument(
        "-E",
        "--exclude-packages",
        dest="excld",
        help="File of Packages to Exclude"
    )
    parser.add_argument(
        "-W",
        "--whitelist-cves",
        dest="whtlst",
        help="File of CVEs to Ignore/Whitelist"
    )
    parser.add_argument(
        '-F',
        '--subfolder',
        dest='subfolder_name',
        help='Name of subfolder to upload to', default=''
    )
    parser.add_argument(
        '-e',
        '--ecosystems',
        dest='ecosystems',
        default="",
        help='Comma separated string of ecosystems that should be used for generating reports'
    )
    parser.add_argument(
        '-s',
        '--subscribe',
        dest='subscribe',
        default="",
        help='Set subscription frequency for sbom report notifications: "none", "daily", "weekly", "monthly"'
    )
    parser.add_argument(
        '--kernel-source',
        dest='kdir',
        default='',
        help='Location of custom kernel source directory',
    )
    parser.add_argument(
        '--uboot-source',
        dest='udir',
        default='',
        help='Location of custom uboot source directory',
    )
    parser.add_argument(
        '--download-sbom',
        help='Download Converted SBOM (CycloneDX/SPDX)',
        action='store_true',
    )
    parser.add_argument(
        '--vigiles-bin',
        help='Path to vigiles CLI binary',
    )
    parser.add_argument(
        '--download-sbom-format',
        help='SBOM format to download',
        type=str.lower,
        choices=DOWNLOAD_SBOM_FORMATS,
    )
    parser.add_argument(
        '--download-sbom-version',
        help='SBOM version to download',
    )
    parser.add_argument(
        '--download-sbom-file-type',
        help='SBOM file type to download',
        type=str.lower,
    )
    parser.add_argument(
        '--queue-jobs',
        dest='queue_jobs',
        help='Submit jobs and exit immediately without waiting for results.',
        action='store_true',
        default=False
    )
    parser.add_argument(
        '--timeout',
        type=positive_int,
        default=DEFAULT_JOB_TIMEOUT,
        help='Maximum number of seconds to wait for a background job '
        '(default: %d)' % DEFAULT_JOB_TIMEOUT
    )
    args = parser.parse_args()

    if args.download_sbom and args.queue_jobs:
        parser.error('--download-sbom and --queue-jobs cannot be used together')

    # Validates download-sbom and related args, no-op unless download is requested
    validate_download_options(parser, args)

    set_debug(args.debug)

    vgls = {
        "write_intm": args.write_intm,
        "bdir": os.path.abspath(args.bdir.strip()) if args.bdir else None,
        "odir": os.path.abspath(args.odir.strip()) if args.odir else None,
        "manifest_name": args.manifest_name.strip(),
        "llkey": os.path.abspath(args.llkey.strip()) if args.llkey else "",
        "lldashboard": os.path.abspath(args.lldashboard.strip()) if args.lldashboard else "",
        "upload_only": args.upload_only,
        "queue_jobs": args.queue_jobs,
        "timeout": args.timeout,
        "kconfig": args.kconfig,
        "uconfig": args.uconfig,
        "addl": os.path.abspath(args.addl.strip()) if args.addl else "",
        "excld": os.path.abspath(args.excld.strip()) if args.excld else "",
        "whtlst": os.path.abspath(args.whtlst.strip()) if args.whtlst else "",
        'subfolder_name': args.subfolder_name.strip(),
        "do_check": args.do_check,
        "ecosystems": args.ecosystems.strip(),
        "subscribe": args.subscribe.strip(),
        "kdir": os.path.abspath(args.kdir.strip()) if args.kdir else None,
        "udir": os.path.abspath(args.udir.strip()) if args.udir else None,
        "download_sbom": args.download_sbom,
        "vigiles_bin": os.path.abspath(args.vigiles_bin.strip()) if args.vigiles_bin else "",
        "download_sbom_format": args.download_sbom_format.strip() if args.download_sbom_format else "",
        "download_sbom_version": args.download_sbom_version.strip() if args.download_sbom_version else "",
        "download_sbom_file_type": args.download_sbom_file_type.strip() if args.download_sbom_file_type else "",
    }

    if not os.path.exists(vgls.get("bdir")):
        err("Invalid path for Openwrt Build directory")
        sys.exit(1)

    if vgls["kdir"] and not os.path.exists(vgls["kdir"]):
        err("Invalid path for Kernel source directory")
        sys.exit(1)

    if vgls["kdir"] and not os.path.exists(os.path.join(vgls["kdir"], "Makefile")):
        err("Invalid Kernel source directory: Makefile not found")
        sys.exit(1)

    if vgls["udir"] and not os.path.exists(vgls["udir"]):
        err("Invalid path for U-Boot source directory")
        sys.exit(1)

    if vgls["udir"] and not os.path.exists(os.path.join(vgls["udir"], "Makefile")):
        err("Invalid U-Boot source directory: Makefile not found")
        sys.exit(1)

    if not vgls.get("odir", None):
        odir = os.path.join(os.path.abspath(os.path.curdir), VIGILES_OUTPUT_DIR)
        if not os.path.exists(odir):
            os.mkdir(odir)
        vgls["odir"] = odir

    dbg("Vigiles OpenWrt Config: %s" % json.dumps(vgls, indent=4, sort_keys=True))
    return vgls


def collect_metadata(vgls):
    dbg("Getting Config Info ...")
    vgls["config"] = get_config_options(vgls)
    if not vgls["config"]:
        sys.exit(1)

    dbg("Getting Package List ...")
    vgls["packages"] = packages.get_package_info(vgls)

    dbg("Getting Package Dependencies ...")
    packages.get_package_dependencies(vgls)

    if not vgls["packages"]:
        sys.exit(1)

    if "linux" in vgls["packages"]:
        dbg("Getting Kernel Info ...")
        get_kernel_info(vgls)

    dbg("Getting U-Boot Info ...")
    get_uboot_info(vgls)

    dbg("Getting Package Checksum Info ...")
    packages.get_pkg_checksums(vgls)


def run_check(vgls):
    kconfig_path = ""
    _kconfig = vgls.get("kconfig", "none")
    if _kconfig != "none" and os.path.exists(_kconfig):
        kconfig_path = _kconfig

    uconfig_path = ""
    _uconfig = vgls.get("uconfig", "none")
    if _uconfig != "none" and os.path.exists(_uconfig):
        uconfig_path = _uconfig

    vgls_chk = {
        "keyfile": vgls.get("llkey", ""),
        "manifest": vgls.get("manifest", ""),
        "report": vgls.get("report", ""),
        "dashboard": vgls.get("lldashboard", ""),
        "upload_only": vgls.get("upload_only", False),
        "kconfig": kconfig_path,
        "uconfig": uconfig_path,
        'subfolder_name': vgls.get('subfolder_name', ''),
        "ecosystems": vgls.get("ecosystems", ""),
        "subscribe": vgls.get("subscribe"),
        "queue_jobs": vgls.get("queue_jobs", False),
        "timeout": vgls.get("timeout", DEFAULT_JOB_TIMEOUT),
    }
    return vigiles_request(vgls_chk)


def __main__():
    vgls = parse_args()
    collect_metadata(vgls)
    write_manifest(vgls)
    if vgls["do_check"]:
        try:
            result = run_check(vgls)
        except Exception as exc:
            print("Vigiles ERROR: %s" % exc, file=sys.stderr)
            sys.exit(1)

        if vgls.get("download_sbom"):
            download_sbom(vgls, result)


__main__()
