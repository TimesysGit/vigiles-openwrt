###########################################################################
#
# lib/utils.py - Miscellaneous Helpers
#
# Copyright (C) 2021 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################################

import errno
import json
import os
import sys


Vigiles_Debug = False
Vigiles_Verbose = True
Previous_Verbose = True


# Case conversion helpers --
# Make and Kconfig uses UPPERCASE_WITH_UNDERSCORES, but for dictionary
# names, we use lowercase-with-dashes.
# These helpers help to do it cleanly throughout.
def py_to_kconfig(name):
    return name.replace("-", "_").upper()


def kconfig_to_py(name):
    return name.replace("_", "-").lower()


def kconfig_bool(value):
    """Helper to parse an affirmative either from make or kconfig"""
    positive = ["y", "yes", "true"]
    negative = ["n", "no", "false"]
    lcase = value.lower()
    if lcase in positive:
        return True
    elif lcase in negative:
        return False
    else:
        return value


def set_debug(enable=True):
    global Vigiles_Debug, Vigiles_Verbose, Previous_Verbose
    Vigiles_Debug = enable
    if enable:
        Previous_Verbose = Vigiles_Verbose
        Vigiles_Verbose = True
    else:
        Vigiles_Verbose = Previous_Verbose


def _print_list(tag, s_list, fp=sys.stdout):
    msg = "\n\t".join(s_list)
    print("Vigiles %s: %s" % (tag, msg), file=fp)


def dbg(msg, extra=[]):
    global Vigiles_Debug
    if Vigiles_Debug:
        s_list = [msg] + extra
        _print_list("DEBUG", s_list)


def info(msg, extra=[]):
    global Vigiles_Verbose
    if Vigiles_Verbose:
        s_list = [msg] + extra
        _print_list("INFO", s_list)


def warn(msg, extra=[]):
    s_list = [msg] + extra
    _print_list("WARNING", s_list, fp=sys.stderr)


def err(msg, extra=[]):
    if not isinstance(msg, list):
        msg = [msg]
    s_list = msg + extra
    _print_list("ERROR", s_list, fp=sys.stderr)


def mkdirhier(directory):
    """Create a directory like 'mkdir -p', but does not complain if
    directory already exists like os.makedirs
    Borrowed from bitbake utils.
    """
    try:
        os.makedirs(directory)
    except OSError as e:
        if e.errno != errno.EEXIST or not os.path.isdir(directory):
            raise e


def write_intm_json(vgls, name, d):
    vdir = vgls["odir"]
    f_dir = os.path.join(vdir, "debug")
    f_path = os.path.join(f_dir, ".".join([name, "json"]))

    mkdirhier(f_dir)

    if vgls["write_intm"]:
        try:
            with open(f_path, "w") as fd:
                print(
                    "%s"
                    % json.dumps(d, indent=4, separators=(",", ": "), sort_keys=True),
                    file=fd,
                    flush=True,
                )
        except Exception as e:
            warn(
                [
                    "Could not write intermediate file.",
                    "File Path: %s" % f_path,
                    "Error: %s" % e,
                ]
            )


def sanitize_openwrt_version(ver):
    if ver.startswith("v"):
        return ver[1:]
    return ver