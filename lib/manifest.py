############################################################################
#
# lib/manifest.py - Helpers for building a Vigiles (OpenWrt) SBOM
#
# Copyright (C) 2021 Timesys Corporation
# Copyright (C) 2025 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
###########################################################################

import json
import os
import subprocess
import time

from .utils import mkdirhier
from .utils import dbg, info, warn

from .amendments import amend_manifest
from .packages import PACKAGE_SUPPLIER, PACKAGE_SUPPLIER_BASE


VIGILES_DEFAULT_DISTRO = "openwrt"
VIGILES_DEFAULT_IMAGE = "rootfs"
VIGILES_MANIFEST_VERSION = "1.3"
VIGILES_OUTPUT_DIR = "vigiles-output"
VIGILES_MANIFEST_NAME_MAX_LENGTH = 256


def _get_firmware_version(vgls, fallback):
    config = vgls["config"]
    subtarget = config.get("config-target-subtarget", "generic")
    libc = config.get("config-libc")

    if libc and libc != "musl" and not config.get("config-external-toolchain"):
        subtarget += "-" + libc

    profiles_path = os.path.join(
        vgls["bdir"], config.get("config-binary-folder") or "bin",
        "targets", config.get("config-target-board", ""), subtarget,
        "profiles.json",
    )

    try:
        with open(profiles_path, encoding="utf-8") as f:
            metadata = json.load(f)
    except (OSError, ValueError):
        return fallback

    version = metadata.get("version_number") if isinstance(metadata, dict) else None
    return version.strip() if isinstance(version, str) and version.strip() else fallback


def _get_config_string(config, key):
    value = config.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _get_package_supplier(config):
    manufacturer = _get_config_string(config, "config-version-manufacturer")
    manufacturer_url = _get_config_string(config, "config-version-manufacturer-url")
    if manufacturer is None and manufacturer_url is None:
        return PACKAGE_SUPPLIER

    return "Organization: %s (%s)" % (
        manufacturer or PACKAGE_SUPPLIER_BASE,
        manufacturer_url or "",
    )


def _get_machine_name(vgls):
    _machine = vgls["config"].get("config-cpu-type", vgls["config"]["config-arch"])
    return _machine


def _limit_manifest_name_length(name, max_limit):
    if len(name) > max_limit:
        warn("Manifest Name: Only the first %d characters will be used for the manifest name." % max_limit)
    return name[:max_limit]


def _init_manifest(vgls):
    def _stripped_packages(pkgs):
        excluded_fields = ["builddir", "is-virtual", "srcdir"]
        return {
            pkgname: {
                k.replace("-", "_"): v
                for k, v in pdict.items()
                if k not in excluded_fields
            }
            for pkgname, pdict in pkgs.items()
        }

    try:
        _distro_version = (
            subprocess.check_output("git describe", cwd=vgls["bdir"], shell=True)
            .splitlines()[0]
            .decode()
        )
    except Exception as e:
        warn("Could not determine Openwrt distro version")
        warn("\tError: %s" % e)
        _distro_version = "Release"

    _boardname = vgls["config"].get("config-target-board", "openwrt")
    _machine = _get_machine_name(vgls)
    _name = vgls.get("manifest_name")
    if not _name:
        _name = _boardname

    _name = _limit_manifest_name_length(_name, VIGILES_MANIFEST_NAME_MAX_LENGTH)
    _root_component = {
        "name": _get_config_string(vgls["config"], "config-version-product") or VIGILES_DEFAULT_IMAGE,
        "version": (
            _get_config_string(vgls["config"], "config-version-number")
            or _get_firmware_version(vgls, _distro_version)
        ),
        "package_supplier": PACKAGE_SUPPLIER,
    }

    build_dict = {
        "arch": vgls["config"]["config-arch"],
        "cpu": vgls["config"].get("config-cpu-type", ""),
        "date": time.strftime("%Y-%m-%d", time.gmtime()),
        "distro": VIGILES_DEFAULT_DISTRO,
        "distro_version": _distro_version,
        "hostname": _boardname,
        "image": VIGILES_DEFAULT_IMAGE,
        "machine": _machine,
        "manifest_name": _name,
        "manifest_version": VIGILES_MANIFEST_VERSION,
        "root_component": _root_component,
        "packages": _stripped_packages(vgls["packages"]),
    }
    return build_dict


def _make_file_name(vgls, manifest_dict, suffix, ext):
    file_spec = "-".join([manifest_dict["manifest_name"][:VIGILES_MANIFEST_NAME_MAX_LENGTH - len(suffix) - len(ext) - 3], suffix])
    file_name = ".".join([file_spec, ext])
    file_path = os.path.join(vgls["odir"], file_name)
    return file_path


def _manifest_name(vgls, manifest_dict):
    return _make_file_name(vgls, manifest_dict, "manifest", "json")


def _report_name(vgls, manifest_dict):
    return _make_file_name(vgls, manifest_dict, "report", "txt")


def write_manifest(vgls):
    final = _init_manifest(vgls)
    vgls["manifest_name"] = final["manifest_name"]

    amend_manifest(vgls, final)

    package_supplier = _get_package_supplier(vgls["config"])
    if package_supplier != PACKAGE_SUPPLIER:
        final["root_component"]["package_supplier"] = package_supplier
        for package in final["packages"].values():
            if package.get("package_supplier") == PACKAGE_SUPPLIER:
                package["package_supplier"] = package_supplier

    vgls["manifest"] = _manifest_name(vgls, final)
    vgls["report"] = _report_name(vgls, final)

    mkdirhier(vgls["odir"])
    info("Writing Manifest to %s" % vgls["manifest"])
    with open(vgls["manifest"], "w") as f:
        json.dump(final, f, indent=4, separators=(",", ": "), sort_keys=True)
        f.write("\n")
