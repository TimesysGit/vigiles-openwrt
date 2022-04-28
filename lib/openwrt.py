###########################################################################
#
# lib/openwrt.py - Helpers for parsing OpenWrt .config variables
#
# Copyright (C) 2021 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################################

import os
from collections import defaultdict

from .utils import kconfig_to_py, kconfig_bool
from .utils import write_intm_json
from .utils import dbg, err, UNKNOWN


def _find_dot_config(vgls):
    odir_dot_config = os.path.join(vgls["bdir"], ".config")
    if os.path.exists(odir_dot_config):
        return odir_dot_config
    else:
        return None


def get_config_options(vgls):
    config_dict = defaultdict()
    config_options = []

    dot_config = _find_dot_config(vgls)
    if not dot_config:
        err(
            [
                "No openwrt .config found.",
                "Please configure the openwrt build.",
                "Or, specify the build directory on the command line",
            ]
        )
        return None

    dbg("Using OpenWrt Config at %s" % dot_config)
    try:
        with open(dot_config, "r") as config_in:
            config_options = [
                f_line.strip() for f_line in config_in if f_line.startswith("CONFIG")
            ]
    except Exception as e:
        err(
            [
                "Could not read/parse openwrt .config",
                "File: %s" % dot_config,
                "Error: %s" % e,
            ]
        )
        return None

    for opt in config_options:
        key, value = opt.split("=", 1)
        key = kconfig_to_py(key)
        value = kconfig_bool(value.replace('"', ""))
        config_dict[key] = value

    dbg("Openwrt Config: %d Options" % len(config_dict.keys()))
    write_intm_json(vgls, "config-vars", config_dict)
    return config_dict


def get_openwrt_license(vgls):
    # Reference: https://git.openwrt.org/?p=openwrt/openwrt.git;a=commit;h=882e3014610be8ec9a2feb63b544b917c39b8293
    if os.path.isdir(os.path.join(vgls["bdir"], "LICENSES")):
        return " or ".join(os.listdir(os.path.join(vgls["bdir"], "LICENSES")))
    elif os.path.isfile(os.path.join(vgls["bdir"], "LICENSE")):
        # All older releases are under "GPLv2"
        return "GPL-2.0"
    return UNKNOWN