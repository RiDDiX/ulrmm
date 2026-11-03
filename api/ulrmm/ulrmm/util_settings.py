# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""URL and domain helpers used while settings are being assembled.

Imported by ``ulrmm.settings`` before Django is configured, so it must
not import ``django.conf.settings`` or anything that does.
"""

from urllib.parse import urlparse

import tldextract

# use the snapshot bundled with tldextract; never fetch the suffix list
_extract = tldextract.TLDExtract(suffix_list_urls=())


def get_webdomain(url: str) -> str:
    return urlparse(url).netloc


def get_root_domain(subdomain: str) -> str:
    parts = _extract(subdomain)
    return f"{parts.domain}.{parts.suffix}"


def get_backend_url(subdomain: str, proto: str, port) -> str:
    url = f"{proto}://{subdomain}"
    if port:
        url = f"{url}:{port}"
    return url
