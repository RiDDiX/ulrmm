# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# build context is the repo root

FROM node:24-bookworm-slim AS web
ARG ULRMM_WEB_REPO=https://github.com/RiDDiX/ulrmm-web.git
ARG ULRMM_WEB_REF=main
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
# the repo may need access: a BuildKit secret "web_token" is used when present
# (compose.yml build.secrets, release.yml), anonymous otherwise
RUN --mount=type=secret,id=web_token \
  GIT_TERMINAL_PROMPT=0 git -c credential.helper='!f() { echo username=git; echo "password=$(cat /run/secrets/web_token 2>/dev/null)"; }; f' \
    clone --depth 1 --branch "$ULRMM_WEB_REF" "$ULRMM_WEB_REPO" /src
WORKDIR /src
RUN npm ci && npm run build && test -f dist/index.html

FROM nginx:1.28
LABEL org.opencontainers.image.licenses="FSL-1.1-ALv2" \
      org.opencontainers.image.source="https://github.com/RiDDiX/ulrmm"
# a new volume takes the owner of the first image it is created from; the api
# services (uid 1000) write /certs and the agent CA, nginx runs as root
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/* \
  && rm -f /etc/nginx/conf.d/default.conf \
  && mkdir -p /etc/nginx/sites-enabled /var/www/rmm \
  && install -d -o 1000 -g 1000 /certs /etc/ulrmm/agent-ca \
  && ln -sf /dev/stdout /var/log/nginx/frontend-access.log \
  && ln -sf /dev/stderr /var/log/nginx/frontend-error.log
COPY --from=web /src/dist /var/www/rmm/dist
COPY LICENSE.md NOTICE.md THIRD_PARTY_NOTICES.md /usr/share/doc/ulrmm/
COPY riddix/scripts/install_lib.sh /opt/ulrmm/install_lib.sh
COPY docker/nginx/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
