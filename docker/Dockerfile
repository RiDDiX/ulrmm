# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Build context is the repo root:
#   docker build -f docker/Dockerfile --target api .
#   docker build -f docker/Dockerfile --target natsapi .

FROM python:3.12-slim-bookworm AS api-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libpcre2-dev libssl-dev libffi-dev && \
    rm -rf /var/lib/apt/lists/*
COPY api/ulrmm/requirements.txt /tmp/requirements.txt
RUN python -m venv /rmm/api/env && \
    /rmm/api/env/bin/pip install --no-cache-dir -r /tmp/requirements.txt

FROM python:3.12-slim-bookworm AS api
LABEL org.opencontainers.image.licenses="FSL-1.1-ALv2" \
      org.opencontainers.image.source="https://github.com/RiDDiX/ulrmm"
# nsis: the agents service builds the Windows setups; osslsigncode signs them
# when Windows signing is configured
RUN apt-get update && apt-get install -y --no-install-recommends \
      git openssl curl ca-certificates postgresql-client jq \
      libpango-1.0-0 libpangoft2-1.0-0 nsis osslsigncode && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -u 1000 -m -s /bin/bash ulrmm
COPY --from=api-builder /rmm/api/env /rmm/api/env
COPY LICENSE.md NOTICE.md THIRD_PARTY_NOTICES.md /usr/share/doc/ulrmm/
COPY --chown=ulrmm:ulrmm VERSION /rmm/VERSION
COPY --chown=ulrmm:ulrmm api/ /rmm/api/
COPY --chown=ulrmm:ulrmm riddix/ /rmm/riddix/
COPY --chown=ulrmm:ulrmm docker/uwsgi.ini /rmm/docker/uwsgi.ini
COPY --chown=ulrmm:ulrmm docker/api/ /rmm/docker/api/
COPY docker/api/init.sh /init.sh
# the volumes take the owner of these directories on their first mount
RUN rm -f /rmm/api/ulrmm/ulrmm/local_settings.py && \
    ln -s /settings/local_settings.py /rmm/api/ulrmm/ulrmm/local_settings.py && \
    install -d -o ulrmm -g ulrmm /settings /conf /certs /mesh-data \
      /etc/ulrmm/agent-ca /opt/ulrmm-agents /opt/ulrmm-community-scripts \
      /rmm/api/ulrmm/static /rmm/api/ulrmm/ulrmm/private && \
    chmod 755 /rmm/docker/api/entrypoint.sh /init.sh
USER ulrmm
WORKDIR /rmm/api/ulrmm
# docker compose exec api python manage.py ... without the entrypoint
ENV PATH=/rmm/api/env/bin:$PATH
ENTRYPOINT ["/rmm/docker/api/entrypoint.sh"]
CMD ["uwsgi", "--ini", "/rmm/docker/uwsgi.ini"]

FROM golang:1.27 AS natsapi-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go VERSION ./
COPY natsapi/ natsapi/
# same flags as riddix/scripts/build_natsapi.sh
RUN CGO_ENABLED=0 GOFLAGS='-mod=readonly -buildvcs=false' \
    go build -trimpath -ldflags "-s -w -X main.version=$(tr -d '[:space:]' <VERSION)" \
      -o /nats-api . && \
    [ "$(/nats-api -version | head -1)" = "$(tr -d '[:space:]' <VERSION)" ]

FROM gcr.io/distroless/static-debian12 AS natsapi
LABEL org.opencontainers.image.licenses="FSL-1.1-ALv2" \
      org.opencontainers.image.source="https://github.com/RiDDiX/ulrmm"
COPY --from=natsapi-builder /nats-api /usr/local/bin/nats-api
# THIRD_PARTY_NOTICES.md carries the licenses of the Go modules in nats-api
COPY LICENSE.md NOTICE.md THIRD_PARTY_NOTICES.md /usr/share/doc/ulrmm/
# same uid as the api image: init writes /conf/nats-api.conf with mode 600
USER 1000:1000
CMD ["/usr/local/bin/nats-api", "-config", "/conf/nats-api.conf"]
