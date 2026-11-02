# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# build context is the repo root. MESH_VER must match settings.py.

FROM node:24-bookworm-slim
LABEL org.opencontainers.image.licenses="FSL-1.1-ALv2" \
      org.opencontainers.image.source="https://github.com/RiDDiX/ulrmm"
ARG MESH_VER=1.2.4
ENV NODE_ENV=production
RUN apt-get update && apt-get install -y --no-install-recommends jq && rm -rf /var/lib/apt/lists/*
WORKDIR /meshcentral
# same pins as mesh_package_json in install.sh
RUN printf '{"dependencies": {"archiver": "7.0.1", "meshcentral": "%s", "otplib": "13.4.1", "pg": "8.16.3"}}\n' "$MESH_VER" >package.json \
  && npm install && npm cache clean --force \
  && mkdir -p meshcentral-data && chown -R node:node /meshcentral
COPY LICENSE.md NOTICE.md THIRD_PARTY_NOTICES.md /usr/share/doc/ulrmm/
COPY --chmod=0755 docker/mesh/entrypoint.sh /entrypoint.sh
USER node
EXPOSE 4430
ENTRYPOINT ["/entrypoint.sh"]
