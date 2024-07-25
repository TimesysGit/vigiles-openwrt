###########################################################
#
# lib/checkcves.py - Online CVE Database Interface.
#
# Copyright (C) 2021 Timesys Corporation
#
#
# This source is released under the MIT License.
#
###########################################################

import argparse
import os
import sys
import json
import urllib.parse

from lib import llapi as ll
from lib.utils import warn

NVD_BASE_URL = "https://nvd.nist.gov/vuln/detail/"
API_DOC = 'https://linuxlink.timesys.com/docs/wiki/engineering/LinuxLink_Key_File'
INFO_PAGE_DOMAIN = "https://www.timesys.com"
INFO_PAGE_PATH = "/security/vulnerability-patch-notification/"
INFO_PAGE = INFO_PAGE_DOMAIN + INFO_PAGE_PATH


bogus_whitelist = "CVE-1234-1234"

ALMALINUX = ['AlmaLinux', 'AlmaLinux:8', 'AlmaLinux:9']
ALPINE = ['Alpine', 'Alpine:v3.10', 'Alpine:v3.11', 'Alpine:v3.12', 'Alpine:v3.13', 'Alpine:v3.14', 'Alpine:v3.15', 'Alpine:v3.16', 'Alpine:v3.17', 'Alpine:v3.18', 'Alpine:v3.19', 'Alpine:v3.2', 'Alpine:v3.20', 'Alpine:v3.3', 'Alpine:v3.4', 'Alpine:v3.5','Alpine:v3.6', 'Alpine:v3.7', 'Alpine:v3.8', 'Alpine:v3.9']
DEBIAN = ['Debian', 'Debian:10', 'Debian:11', 'Debian:12', 'Debian:13', 'Debian:3.0', 'Debian:3.1', 'Debian:4.0', 'Debian:5.0', 'Debian:6.0', 'Debian:7', 'Debian:8', 'Debian:9']
ROCKY = ['Rocky Linux', 'Rocky Linux:8', 'Rocky Linux:9']
UBUNTU = ['Ubuntu', 'Ubuntu:14.04:LTS', 'Ubuntu:16.04:LTS', 'Ubuntu:18.04:LTS', 'Ubuntu:20.04:LTS', 'Ubuntu:22.04:LTS', 'Ubuntu:23.10', 'Ubuntu:24.04:LTS', 'Ubuntu:Pro:14.04:LTS', 'Ubuntu:Pro:16.04:LTS', 'Ubuntu:Pro:18.04:LTS', 'Ubuntu:Pro:20.04:LTS', 'Ubuntu:Pro:22.04:LTS', 'Ubuntu:Pro:24.04:LTS']
OTHERS = ['Android', 'Bitnami', 'CRAN', 'GIT', 'GSD', 'GitHub Actions', 'Go', 'Hackage', 'Hex', 'Linux', 'Maven', 'NuGet', 'OSS-Fuzz', 'Packagist', 'Pub', 'PyPI', 'RubyGems', 'SwiftURL', 'UVI', 'crates.io', 'npm']

ALL_ECOSYSTEMS = OTHERS + ALMALINUX + ALPINE + DEBIAN + ROCKY + UBUNTU


class InvalidDashboardConfig(BaseException):
    pass


class InvalidLinuxlinkKey(BaseException):
    pass


def get_usage():
    return (
        "This script sends a json manifest file for an image to LinuxLink "
        "to check the CVE status of the recipes. The manifest must be "
        "specified. \n\n"
        "A full report a LinuxLink API keyfile, and an active LinuxLink "
        "subscription.\n\n"
        "See this document for keyfile information:\n"
        "%s\n\n" % API_DOC
    )


def print_demo_notice(bad_key=False):
    print("\n-- Vigiles Demo Mode Notice --", file=sys.stderr)

    if bad_key:
        print(
            "\tNo API keyfile was found, or the contents were invalid.\n\n"
            "\tPlease see this document for API key information:\n"
            "\t%s\n" % API_DOC,
            file=sys.stderr,
        )
    else:
        print("\tNo active subscription for this account.\n", file=sys.stderr)

    print(
        "\tThe script will continue in demo mode, which will link you to "
        "temporarily available online results only.\n"
        "\tTo request a trial account, please contact us at sales@timesys.com\n",
        file=sys.stderr,
    )
    print(
        "\tFor more information on the security notification service, "
        "please visit:\n"
        "\t%s\n" % INFO_PAGE,
        file=sys.stderr,
    )


def handle_cmdline_args():
    parser = argparse.ArgumentParser(description=get_usage())
    parser.add_argument(
        "-o",
        "--outfile",
        help="Print results to FILE instead of STDOUT",
        metavar="FILE",
    )
    parser.add_argument(
        "-k",
        "--kconfig",
        help="Full Kernel .config to submit for CVE filtering",
        metavar="FILE",
        dest="kconfig",
    )
    parser.add_argument(
        "-u",
        "--uboot-config",
        help="Full U-Boot .config to submit for CVE filtering",
        metavar="FILE",
        dest="uboot_config",
    )
    parser.add_argument(
        "-F",
        "--subfolder-name",
        help="Name of subfolder to upload to",
        dest="subfolder_name",
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "-m", "--manifest", help="JSON image manifest file to check", metavar="FILE"
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
    return parser.parse_args()


def read_manifest(manifest_file):
    try:
        with open(manifest_file, "r") as f:
            manifest_data = "".join(line.rstrip() for line in f)
    except (OSError, IOError, UnicodeDecodeError) as e:
        print("Error: Could not open manifest: %s" % e)
        sys.exit(1)
    return manifest_data


def print_cves(result, outfile=None):
    cves = result.get("cves", {})
    if cves:
        print("\n\n-- Recipe Vulnerabilities --", file=outfile)
        for pkg, info in cves.items():
            for cve in info:
                print("\n\tRecipe:  %s" % pkg, file=outfile)
                print("\tVersion: %s" % cve.get("version"), file=outfile)
                print("\tID:      %s" % cve.get("cve_id"), file=outfile)
                print("\tURL:     %s%s" % (NVD_BASE_URL, cve.get("cve_id")), file=outfile)
                print("\tCVSSv3:  %s" % cve.get("cvss"), file=outfile)
                print("\tVector:  %s" % cve.get("vector"), file=outfile)
                print("\tStatus:  %s" % cve.get("status"), file=outfile)
                patches = cve.get("fixedby")
                if patches:
                    print("\tPatched by:", file=outfile)
                    for patch in patches:
                        print("\t* %s" % patch, file=outfile)


def print_ecosystem_vulns(result, outfile=None):
    vuln_keys = [
        "ASB",
        "CAN",
        "DLA",
        "DSA",
        "DTSA",
        "GHSA",
        "GO",
        "GSD",
        "GSD",
        "OSV",
        "PYSEC",
        "RUSTSEC",
        "UVI",
    ]
    for key in vuln_keys:
        vulns = result.get(key)
        if vulns:
            for pkg, info in vulns.items():
                for vuln in info:
                    print('\n\tRecipe:  %s' % pkg, file=outfile)
                    version = vuln.get('database_specific', {}).get('version')
                    if version:
                        print('\tVersion: %s' % version, file=outfile)
                    
                    print('\tID:      %s' % vuln.get('id'), file=outfile)
                    affected = vuln.get("affected", [])
                    sources = set()
                    for info in affected:
                        source = info.get("database_specific", {}).get("source")
                        if source and source not in sources:
                            sources.add(source)
                            print('\tURL:     %s' % source, file=outfile)
                    print('\tVector:  %s' % vuln.get('vector'), file=outfile)
                    print('\tStatus:  %s' % vuln.get('status', 'Unfixed'), file=outfile)


def parse_unfixed_cve_counts(counts):
    total = counts.get("unfixed", 0) + counts.get("unapplied", 0) + counts.get("upgradable", 0)
    kernel = counts.get("kernel", {}).get("unfixed", 0) + \
             counts.get("kernel", {}).get("unapplied", 0) + \
             counts.get("kernel", {}).get("upgradable", 0)
    userspace = total - kernel
    return {"total": total, "userspace": userspace, "kernel": kernel}


def parse_fixed_cve_counts(counts):
    total = counts.get("fixed", 0)
    kernel = counts.get("kernel", {}).get("fixed", 0)
    userspace = total - kernel
    return {"total": total, "userspace": userspace, "kernel": kernel}


def parse_cvss_counts(counts):
    high_cvss_total = counts.get("high", {}).get("unfixed", 0)
    high_cvss_kernel = counts.get("kernel", {}).get("high", {}).get("unfixed", 0)
    critical_cvss_total = counts.get("critical", {}).get("unfixed", 0)
    critical_cvss_kernel = counts.get("kernel", {}).get("critical", {}).get("unfixed", 0)
    total = high_cvss_total + critical_cvss_total
    kernel = high_cvss_kernel + critical_cvss_kernel
    userspace = total - kernel
    return {"total": total, "userspace": userspace, "kernel": kernel}


def print_report_header(result, f_out=None):
    from datetime import datetime

    report_time = result.get("date", datetime.utcnow().isoformat())

    print("-- Vigiles Vulnerability Scanner --\n\n" "\t%s\n\n" % INFO_PAGE, file=f_out)
    print("-- Date Generated (UTC) --\n", file=f_out)
    print("\t%s" % report_time, file=f_out)


def print_report_overview(result, is_demo=False, f_out=None):
    report_path = result.get("report_path", "")
    product_path = result.get("product_path", "")

    if report_path:
        report_url = urllib.parse.urljoin(ll.VigilesURL, report_path)
        print("\n-- Vigiles Vulnerability Report --", file=f_out)
        print("\n\tView detailed online report at:\n" "\t  %s" % report_url, file=f_out)
    elif product_path:
        product_url = urllib.parse.urljoin(ll.VigilesURL, product_path)
        product_name = result.get("product_name", "Default")
        print("\n-- Vigiles Dashboard --", file=f_out)
        print(
            "\n\tThe manifest has been uploaded to the '%s' Product Workspace:\n\n"
            "\t  %s\n" % (product_name, product_url),
            file=f_out,
        )

    if is_demo:
        print(
            "\t  NOTE: Running in Demo Mode will cause this URL to expire "
            "after one day.",
            file=f_out,
        )


def print_summary(result, outfile=None):
    def show_subscribed_summary(f_out=outfile):
        counts = result.get("counts", {})
        unfixed = parse_unfixed_cve_counts(counts)
        fixed = parse_fixed_cve_counts(counts)

        cvss_counts = counts.get("cvss_counts", {})
        cvss = parse_cvss_counts(cvss_counts)

        print(
            "\n\tUnfixed: {} ({} User space, {} Kernel)".format(
                unfixed["total"],
                unfixed["userspace"],
                unfixed["kernel"],
            ),
            file=f_out,
        )
        print(
            "\tFixed: {} ({} User space, {} Kernel)".format(
                fixed["total"], fixed["userspace"], fixed["kernel"]
            ),
            file=f_out,
        )
        print(
            "\tHigh/Critical CVSS (Unfixed): {} ({} User space, {} Kernel)".format(
                cvss["total"], cvss["userspace"], cvss["kernel"]
            ),
            file=f_out,
        )

    def show_demo_summary(f_out=outfile):
        cves = result.get("cves", {})
        print("\n-- Vigiles Vulnerability Overview --", file=f_out)
        print(
            "\n\tUnfixed: %d\n"
            "\tUnfixed, Patch Available: %d\n"
            "\tFixed: %d"
            % (
                cves.get("unfixed_count"),
                cves.get("unapplied_count"),
                cves.get("fixed_count"),
            ),
            file=f_out,
        )

    is_demo = result.get("demo", False)

    if "counts" in result:
        show_subscribed_summary(outfile)
    elif is_demo:
        show_demo_summary(outfile)


def print_foootnotes(f_out=None):
    print("\n-- Vigiles Footnotes --", file=f_out)
    print(
        '\t* "CPU" Vulnerabilities are filed against the hardware.\n'
        "\t  They may be fixed or mitigated in other components such as "
        "the kernel or compiler.\n",
        file=f_out,
    )

    print(
        '\t* "Whitelist" Recipes and Vulnerabilities are listed in the '
        '"VIGILES_WHITELIST" variable.\n'
        "\t  They are NOT included in the report.\n",
        file=f_out,
    )


def print_whitelist(wl, outfile=None):
    print("\n-- Vigiles Vulnerability Whitelist --\n", file=outfile)
    if wl:
        for item in sorted(wl):
            print("\t* %s" % item, file=outfile)
    else:
        print("\t(Nothing is Whitelisted)", file=outfile)


def check_dashboard_config(dashboard_config, default_dc_used):
    err_prefix = "Invalid Dashboard Config."
    err_suffix = " Report will be generated in Private Workspace instead."
    
    try:
        with open(dashboard_config, "r") as f:
            conf = json.load(f)
            if conf.get("product", conf.get("group")):
                if len(conf) > 1:
                    if conf.get("folder"):
                        return
                else:
                    return
            err_msg = err_prefix + err_suffix
    except FileNotFoundError:
        if default_dc_used:
            return
        err_msg = "Dashboard config doesn't exists at %s." %dashboard_config + err_suffix
    except json.decoder.JSONDecodeError:
        err_msg = err_prefix + err_suffix
    except Exception as e:
        err_msg = "Unable to parse Dashboard config : %s." % e + err_suffix
    raise InvalidDashboardConfig(err_msg)


def check_linuxlink_key(key, default_key_used):
    err_prefix = "Invalid Linuxlink key."
    err_suffix = " Report will be generated in Demo mode instead."
    
    try:
        with open(key, "r") as f:
            ll_key = json.load(f)
            parsed_key = ll_key.get("key", ll_key.get("organization_key"))
            if parsed_key and ll_key.get("email"):
                if len(ll_key) > 2:
                    is_enterprise = ll_key.get("enterprise", False)
                    if isinstance(is_enterprise, bool):
                        return
                else:
                    return
            err_msg = err_prefix + err_suffix
    except FileNotFoundError:
        if default_key_used:
            return
        err_msg = "Linuxlink key doesn't exists at %s." % key + err_suffix
    except json.decoder.JSONDecodeError:
        err_msg = err_prefix + err_suffix
    except Exception as e:
        err_msg = "Unable to parse Linuxlink: %s." % e + err_suffix
    raise InvalidLinuxlinkKey(err_msg)


def _get_credentials(vgls_chk):
    home_dir = os.path.expanduser("~")
    timesys_dir = os.path.join(home_dir, "timesys")

    kf_env = os.getenv("VIGILES_KEY_FILE", "")
    kf_param = vgls_chk.get("keyfile", "")
    kf_default = os.path.join(timesys_dir, "linuxlink_key")

    dc_env = os.getenv("VIGILES_DASHBOARD_CONFIG", "")
    dc_param = vgls_chk.get("dashboard", "")
    dc_default = os.path.join(timesys_dir, "dashboard_config")

    sf_env = os.getenv('VIGILES_SUBFOLDER_NAME', '')
    sf_param = vgls_chk.get('subfolder_name', '')
    sf_default = ''

    default_key_used = False
    default_dc_used = False
    if kf_env:
        print("Vigiles: Using LinuxLink Key from Environment: %s" % kf_env)
        key_file = kf_env
    elif kf_param:
        print("Vigiles: Using LinuxLink Key from Configuration: %s" % kf_param)
        key_file = kf_param
    else:
        print("Vigiles: Trying LinuxLink Key Default: %s" % kf_default)
        key_file = kf_default
        default_key_used = True

    if dc_env:
        print("Vigiles: Using Dashboard Config from Environment: %s" % dc_env)
        dashboard_config = dc_env
    elif dc_param:
        print("Vigiles: Using Dashboard Config Configuration: %s" % dc_param)
        dashboard_config = dc_param
    else:
        print("Vigiles: Trying Dashboard Config Default: %s" % dc_default)
        dashboard_config = dc_default
        default_dc_used = True

    if sf_env:
        print("Vigiles: Using subfolder name from Environment: %s" % sf_env)
        subfolder_name = sf_env
    elif sf_param:
        print("Vigiles: Using subfolder name Configuration: %s" % sf_param)
        subfolder_name = sf_param
    else:
        print("Vigiles: Trying subfolder name Default: %s" % sf_default)
        subfolder_name = sf_default

    vgls_chk["keyfile"] = key_file
    vgls_chk["dashboard"] = dashboard_config
    vgls_creds = {}
    dashboard_tokens = {}

    try:
        check_linuxlink_key(key_file, default_key_used)
        key_info = ll.read_keyfile(key_file)
        email = key_info.get('email', None)
        key = key_info.get('key', key_info.get('organization_key', None))
        is_enterprise = key_info.get('enterprise', False)
        if is_enterprise:
            ll.VigilesURL = key_info.get('server_url', ll.VigilesURL)

        # Validate dashboard config
        # Bypass Validation check for demo mode
        if email and key:
            check_dashboard_config(dashboard_config, default_dc_used)

            # It is fine if either of these are none, they will just default
            dashboard_tokens = ll.read_dashboard_config(dashboard_config)
    
    except InvalidLinuxlinkKey as e:
        print('\nVigiles WARNING: %s\n' % e)
        return vgls_creds
    except InvalidDashboardConfig as e:
        print('\nVigiles WARNING: %s\n' % e)
    except Exception as e:
        print('\nVigiles ERROR: %s\n' % e)
        print(get_usage())
        sys.exit(1)

    if email or key:
        if subfolder_name and not dashboard_tokens.get('product_or_group'):
            warn("Subfolder is specified, but no dashboard config found. SBOM will be uploaded in Private Workspace")

    vgls_creds = {
        "email": email,
        "key": key,
        'product_or_group': dashboard_tokens.get('product_or_group', ''),
        "folder": dashboard_tokens.get("folder", ""),
        'subfolder_name': subfolder_name,
        'is_enterprise': is_enterprise,
    }
    return vgls_creds


def vigiles_request(vgls_chk):
    resource = "/api/v1/vigiles/manifests"

    vgls_creds = _get_credentials(vgls_chk)
    email = vgls_creds.get("email")
    key = vgls_creds.get("key")
    is_enterprise = vgls_creds.get('is_enterprise')
    subfolder_name = vgls_creds.get('subfolder_name')
    demo = False

    # If there was no proper API keyfile, operate in demo mode.
    if not email or not key:
        demo = True
        resource += "/demo"
        print_demo_notice(bad_key=True)

    manifest_path = vgls_chk.get("manifest", "")
    report_path = vgls_chk.get("report", "")
    kconfig_path = vgls_chk.get("kconfig", "")
    uconfig_path = vgls_chk.get("uconfig", "")
    upload_only = vgls_chk.get("upload_only", False)

    if report_path:
        outfile = open(report_path, "w")
    else:
        outfile = None

    # read or create image manifest
    if manifest_path:
        manifest_data = read_manifest(manifest_path)

    manifest = json.loads(manifest_data)
    if len(manifest["packages"]) == 0:
        print("No packages found in manifest.\n")
        sys.exit(1)

    # If -k is specified, the given config file is submitted along with the
    # manifest to filter out irrelevant kernel CVEs
    if not kconfig_path:
        kernel_config = ""
    else:
        try:
            with open(kconfig_path, "r") as kconfig:
                kernel_config = kconfig.read().strip()
        except (OSError, IOError, UnicodeDecodeError) as e:
            print("Error: Could not open kernel config: %s" % e)
            sys.exit(1)
        print(
            "Vigiles: Kernel Config based filtering has been applied from %s"
            % kconfig_path,
            file=sys.stderr,
        )

    # U-Boot and SPL filtering works the same way as kernel config filtering
    if not uconfig_path:
        uboot_config = ""
    else:
        try:
            with open(uconfig_path, "r") as uconfig:
                uboot_config = uconfig.read().strip()
        except (OSError, IOError, UnicodeDecodeError) as e:
            print("Error: Could not open U-Boot config: %s" % e)
            sys.exit(1)
        print(
            "Vigiles: U-Boot Config based filtering has been applied %s" % uconfig_path,
            file=sys.stderr,
        )

    request = {
        "manifest": manifest_data,
        'group_token' if is_enterprise else 'product_token': vgls_creds.get('product_or_group', ''),
        "folder_token": vgls_creds.get("folder", ""),
        "upload_only": upload_only,
        'subfolder_name': subfolder_name,
    }

    if kernel_config:
        request["kernel_config"] = kernel_config

    if uboot_config:
        request["uboot_config"] = uboot_config

    ecosystems = []
    ecosystems_str = vgls_chk.get('ecosystems', '')
    if ecosystems_str:
        if is_enterprise:
            if ecosystems_str.lower() == "all":
                ecosystems = ALL_ECOSYSTEMS
            else:
                invalid_ecosystems = set()
                ecosystems = [esys.strip() for esys in ecosystems_str.split(",")]
                for ecosystem in ecosystems:
                    if ecosystem not in ALL_ECOSYSTEMS:
                        invalid_ecosystems.add(ecosystem)
                if invalid_ecosystems:
                    print('Vigiles WARNING: Skipping invalid ecosystems: %s. Refer to README.md for valid ecosystems.' % ",".join(invalid_ecosystems))
                ecosystems = [e for e in ecosystems if e not in invalid_ecosystems]
            request['ecosystems'] = ",".join(ecosystems)
        else:
            print('Vigiles WARNING: Ecosystems based scanning is available only for enterprise edition')

    subscribe = vgls_chk.get("subscribe")
    valid_subscribe = ["none", "daily", "weekly", "monthly"]
    if subscribe:
        subscribe = subscribe.lower()
        if is_enterprise:
            if subscribe in valid_subscribe:
                request["subscribe"] = subscribe
            else:
                print('Vigiles ERROR: Invalid subscription frequency. Choose from: none, daily, weekly, monthly')
                sys.exit(1)
        else:
            print('Vigiles WARNING: The subscribe option is currently only supported with the Enterprise edition')

    print("Vigiles: Requesting image analysis from {} ...\n".format(
    "Enterprise Vigiles" if is_enterprise else "Linuxlink"), file=sys.stderr)

    result = ll.api_post(email, key, resource, request)
    if not result:
        if outfile:
            outfile.close()
        sys.exit(1)

    # the default list contains a harmless but bogus example CVE ID,
    # don't print it here in case that is confusing.
    whitelist = [
        item
        for item in manifest.get("whitelist", [])
        if not any(bogon == item for bogon in bogus_whitelist.split())
    ]

    print_report_header(result, outfile)
    print_report_overview(result, demo, outfile)

    print_summary(result, outfile=outfile)

    if not demo:
        print_cves(result, outfile=outfile)
        if is_enterprise and ecosystems:
            print_ecosystem_vulns(result, outfile=outfile)

    if not upload_only:
        print_whitelist(whitelist, outfile=outfile)
        print_foootnotes(f_out=outfile)

    if outfile is not None:
        print_report_overview(result, demo)
        print_summary(result)
        print("\n\tLocal summary written to:\n\t  %s" % os.path.relpath(outfile.name))
        outfile.close()


if __name__ == "__main__":
    args = handle_cmdline_args()

    vgls_chk = {
        "manifest": args.manifest,
        "report": args.outfile,
        "kconfig": args.kconfig,
        "uconfig": args.uboot_config,
        'subfolder_name': args.subfolder_name,
        'ecosystems': args.ecosystems.strip(),
        'susbscribe': args.subscribe.strip()
    }
    vigiles_request(vgls_chk)
