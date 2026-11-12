# python:3.13.18-slim-trixie. Digest from `docker buildx imagetools inspect python:3.13-slim`.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Release-asset digests: nuclei 3.11.1 (linux amd64/arm64) and nikto 2.6.0.
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG NIKTO_VERSION=2.6.0
ARG NIKTO_SHA256=3057fce7574168e036715ae7ccf2c04fe9a21864514c69fa0644d02de57ca8c8

RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) nuclei_sha="$NUCLEI_SHA256_AMD64" ;; \
      arm64) nuclei_sha="$NUCLEI_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip" -o /tmp/nuclei.zip; \
    printf '%s  %s\n' "$nuclei_sha" /tmp/nuclei.zip | sha256sum -c -; \
    unzip -q -j /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    chmod 755 /usr/local/bin/nuclei; \
    rm /tmp/nuclei.zip; \
    curl -fsSL "https://github.com/sullo/nikto/releases/download/${NIKTO_VERSION}/nikto-main.zip" -o /tmp/nikto.zip; \
    printf '%s  %s\n' "$NIKTO_SHA256" /tmp/nikto.zip | sha256sum -c -; \
    unzip -q /tmp/nikto.zip -d /tmp; \
    mv /tmp/nikto-main /opt/nikto; \
    chmod 755 /opt/nikto/program/nikto.pl; \
    rm /tmp/nikto.zip

# uv 0.9.13, the version that wrote uv.lock. Digest from `docker buildx imagetools inspect`.
COPY --from=ghcr.io/astral-sh/uv:0.9.13@sha256:f07d1bf7b1fb4b983eed2b31320e25a2a76625bdf83d5ff0208fe105d4d8d2f5 /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# scanners extra conflicts with web and pins known-vulnerable libraries, so it stays out.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --extra web --extra reporting
COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --extra web --extra reporting

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# Pinned base still ships zlib1g +b1; trixie-security has deb13u1.
# Base-image pip vendors vulnerable msgpack, urllib3 and setuptools; the app uses the venv.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl nmap perl \
        libnet-ssleay-perl libio-socket-ssl-perl libjson-perl \
        libxml-writer-perl libxml-libxml-perl \
        zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
    && rm -rf /var/lib/apt/lists/* \
        /usr/local/lib/python3.13/site-packages/pip \
        /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
        /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin haris

COPY --from=build /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=build /opt/nikto /opt/nikto
RUN ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

COPY --from=build /app /app
RUN mkdir -p /app/data /app/reports \
    && chown -R haris:haris /app/data /app/reports

WORKDIR /app
ENV PATH="/app/.venv/bin:${PATH}" \
    HOME=/home/haris \
    PYTHONDONTWRITEBYTECODE=1

USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "--factory", "haris.web.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
