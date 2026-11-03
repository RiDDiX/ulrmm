# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Reporting settings, read on every call so tests and local_settings.py
# overrides take effect without a restart.
from django.conf import settings

ASSETS_URL_PATH = "/reporting/assets/"

# uploads and imports are limited to these extensions
ASSET_EXTENSIONS = frozenset(
    (
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "svg",
        "ico",
        "woff",
        "woff2",
        "ttf",
        "otf",
        "css",
        "pdf",
        "csv",
        "txt",
    )
)

# served inline; everything else, including svg, goes out as an attachment
INLINE_ASSET_EXTENSIONS = frozenset(
    ("png", "jpg", "jpeg", "gif", "webp", "ico", "woff", "woff2", "ttf", "otf")
)


def assets_base_path() -> str:
    return getattr(
        settings, "REPORTING_ASSETS_BASE_PATH", "/opt/ulrmm-reporting/assets"
    )


def base_url() -> str:
    url = getattr(settings, "REPORTING_BASE_URL", None)
    if not url:
        url = f"https://{settings.ALLOWED_HOSTS[0]}"
    return url.rstrip("/")


def assets_base_url() -> str:
    return f"{base_url()}{ASSETS_URL_PATH}"


def max_rows() -> int:
    return int(getattr(settings, "REPORTING_MAX_ROWS", 10_000))


def max_asset_bytes() -> int:
    return int(getattr(settings, "REPORTING_MAX_ASSET_MB", 25)) * 1024 * 1024


def max_import_bytes() -> int:
    return int(getattr(settings, "REPORTING_MAX_IMPORT_MB", 100)) * 1024 * 1024


def render_timeout() -> float:
    return float(getattr(settings, "REPORTING_RENDER_TIMEOUT", 120))


def max_output_chars() -> int:
    return int(getattr(settings, "REPORTING_MAX_OUTPUT_MB", 50)) * 1024 * 1024


def asset_extension(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def is_allowed_asset(name: str) -> bool:
    return asset_extension(name) in ASSET_EXTENSIONS


def is_inline_asset(name: str) -> bool:
    return asset_extension(name) in INLINE_ASSET_EXTENSIONS
