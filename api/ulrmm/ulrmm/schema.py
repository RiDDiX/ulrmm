# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class APIAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "ulrmm.auth.APIAuthentication"
    name = "API Key Auth"

    def get_security_definition(self, auto_schema):
        return {"type": "apiKey", "in": "header", "name": "X-API-KEY"}
