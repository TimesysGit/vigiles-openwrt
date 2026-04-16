###########################################################################
#
# lib/clitasks.py - Helpers for Running Vigiles CLI Tasks
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
###########################################################################

import json
import os
import re
import subprocess

from .utils import dbg, info, warn
from .constants import DOWNLOAD_SBOM_OPTIONS


def _get_status_code(stdout):
    """Extract `status_code` from stdout; return int or None."""
    status_match = re.search(r"['\"]status_code['\"]\s*:\s*(\d+)", stdout)
    if status_match:
        return int(status_match.group(1))
    return None


def validate_download_options(parser, args):
    """
    Validate all download-sbom related arguments at parser time.
    """
    download_args = {
        '--vigiles-bin': args.vigiles_bin,
        '--download-sbom-format': args.download_sbom_format,
        '--download-sbom-version': args.download_sbom_version,
        '--download-sbom-file-type': args.download_sbom_file_type,
    }

    download_requested = args.download_sbom
    used_download_args = [opt for opt, value in download_args.items() if value]

    if not download_requested and used_download_args:
        parser.error(f"--download-sbom must be specified when using: {', '.join(used_download_args)}")

    if not download_requested:
        return

    env_vigiles_bin = os.getenv("VIGILES_BIN_PATH", "").strip()
    if env_vigiles_bin:
        info("Using vigiles-bin path from environment: %s" % env_vigiles_bin)
        args.vigiles_bin = env_vigiles_bin
        download_args['--vigiles-bin'] = args.vigiles_bin

    if not args.download_sbom_file_type:
        args.download_sbom_file_type = "json"

    if not args.download_sbom_version and args.download_sbom_format == "cyclonedx":
        args.download_sbom_version = "1.6"
    elif not args.download_sbom_version and args.download_sbom_format in ("spdx", "spdx-lite"):
        args.download_sbom_version = "2.3"

    missing_required_args = [opt for opt, value in list(download_args.items())[:2] if not value]
    if missing_required_args:
        parser.error(f"--download-sbom is missing required arguments: {', '.join(missing_required_args)}")

    vigiles_bin = args.vigiles_bin.strip()
    if not (os.path.isfile(vigiles_bin) and os.access(vigiles_bin, os.X_OK)):
        parser.error(f"argument --vigiles-bin: path not found or not executable: {vigiles_bin}")

    sbom_format = args.download_sbom_format.strip()
    sbom_file_type = args.download_sbom_file_type.strip()
    sbom_version = args.download_sbom_version.strip()

    allowed_file_types = DOWNLOAD_SBOM_OPTIONS[sbom_format]["file_types"]
    if sbom_file_type not in allowed_file_types:
        parser.error(
            f"argument --download-sbom-file-type: invalid choice: '{sbom_file_type}' "
            f"for format '{sbom_format}' (choose from {', '.join(sorted(allowed_file_types))})"
        )

    allowed_versions = DOWNLOAD_SBOM_OPTIONS[sbom_format]["versions"]
    if sbom_version not in allowed_versions:
        parser.error(
            f"argument --download-sbom-version: invalid choice: '{sbom_version}' "
            f"for format '{sbom_format}' (choose from {', '.join(sorted(allowed_versions, reverse=True))})"
        )


def download_sbom(vgls, result):
    """
    Download a converted SBOM (CycloneDX/SPDX) using a user-provided vigiles-cli binary.
    """
    sbom_token = result.get('manifest_token') if result else None
    if not sbom_token:
        warn("SBOM token not found.")
        return

    keyfile = vgls['llkey']
    vigiles_bin = vgls['vigiles_bin']

    sbom_format = vgls['download_sbom_format']
    sbom_file_type = vgls['download_sbom_file_type']
    sbom_version = vgls['download_sbom_version']

    sbom_name = vgls['manifest_name']
    download_dir = vgls['odir']
    suffix_ext = "spdx" if sbom_file_type == "tag" else sbom_file_type
    output_path = os.path.join(
        download_dir,
        "%s-%s-%s.%s" % (
            sbom_name,
            sbom_format,
            sbom_version.replace(".", "_"),
            suffix_ext,
        )
    )

    cmd = [
        vigiles_bin,
        "-k", keyfile,
        "manifest", "download", sbom_token,
        "-f", sbom_format,
        "-i", sbom_file_type,
        "-v", sbom_version,
        "-o", output_path,
    ]

    info("Downloading %s-%s SBOM" % (sbom_format, sbom_version))
    dbg("Vigiles CLI command: %s" % json.dumps(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
    except Exception as err:
        warn("Failed to download SBOM: %s" % err)
        return

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    status_code = _get_status_code(stdout) if stdout else None

    if stderr:
        warn(stderr)

    if status_code is not None and status_code >= 400:
        warn(stdout)
        return

    if stdout:
        info(stdout)
    if os.path.exists(output_path):
        info("Downloaded SBOM saved to %s" % output_path)
    else:
        warn("Failed to download SBOM")
