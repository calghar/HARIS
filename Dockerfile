FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install system security tools and build dependencies.
# nikto is installed from git (not available in Debian apt repos).
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git ca-certificates unzip jq \
    perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei — auto-detect architecture via GitHub API (supports amd64, arm64, armv6)
RUN ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in \
         amd64) NUCLEI_ARCH="linux_amd64" ;; \
         arm64) NUCLEI_ARCH="linux_arm64" ;; \
         armhf) NUCLEI_ARCH="linux_arm" ;; \
         *)     echo "Unsupported arch: $ARCH"; exit 1 ;; \
       esac \
    && DOWNLOAD_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
       | jq -r ".assets[] | select(.name | test(\"${NUCLEI_ARCH}\")) | .browser_download_url") \
    && echo "Downloading nuclei from: $DOWNLOAD_URL" \
    && curl -sSfL "$DOWNLOAD_URL" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -version

# Templates are persisted at runtime via the nuclei-data Docker volume.
RUN nuclei -update-templates \
    || echo "nuclei template pre-fetch failed — will download on first run"

WORKDIR /app

# Copy application code and install (non-editable)
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[all]" && mkdir -p /app/reports

EXPOSE 8000

CMD ["uvicorn", "haris.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
