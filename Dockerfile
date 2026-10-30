# Use Python 3.12 on Debian Bookworm (stable) for reliable apt repos
FROM python:3.12-slim-bookworm

# Tool versions
ARG TARGETARCH
ARG SUBFINDER_VERSION=2.17.0
ARG AMASS_VERSION=5.0.1

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Ensure Playwright browsers are installed to a persistent, non-cache path
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install dependencies with aggressive space optimization
RUN set -eux && \
    # Configure apt to minimize cache
    echo 'APT::Install-Recommends "0";' > /etc/apt/apt.conf.d/99-no-recommends && \
    echo 'APT::Install-Suggests "0";' > /etc/apt/apt.conf.d/99-no-suggests && \
    echo 'APT::Keep-Downloaded-Packages "false";' > /etc/apt/apt.conf.d/99-no-cache && \
    # Update package lists and install dependencies
    apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates unzip && \
    # Install subdomain enumeration tools with checksum verification
    TOOL_ARCH="${TARGETARCH:-amd64}" && \
    case "$TOOL_ARCH" in amd64|arm64) ;; *) echo "Unsupported Docker TARGETARCH: $TOOL_ARCH" >&2; exit 1 ;; esac && \
    SUBFINDER_ARCHIVE="subfinder_${SUBFINDER_VERSION}_linux_${TOOL_ARCH}.zip" && \
    AMASS_ARCHIVE="amass_linux_${TOOL_ARCH}.tar.gz" && \
    AMASS_DIR="amass_linux_${TOOL_ARCH}" && \
    case "$TOOL_ARCH" in \
      amd64) \
        SUBFINDER_SHA256='a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37'; \
        AMASS_SHA256='ca0682b7f504c7016e8991505aa1bf343b1bf02e64946ce8575891bda037b8e6' ;; \
      arm64) \
        SUBFINDER_SHA256='24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190'; \
        AMASS_SHA256='286403bcb0e8dcf8e989f76584a848b179007872ed5258234f77810babf6b771' ;; \
    esac && \
    wget -qO "/tmp/${SUBFINDER_ARCHIVE}" "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/${SUBFINDER_ARCHIVE}" && \
    echo "${SUBFINDER_SHA256}  /tmp/${SUBFINDER_ARCHIVE}" | sha256sum --check && \
    mkdir -p /tmp/subfinder && \
    unzip -q "/tmp/${SUBFINDER_ARCHIVE}" -d /tmp/subfinder && \
    mv /tmp/subfinder/subfinder /usr/local/bin/subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    wget -qO "/tmp/${AMASS_ARCHIVE}" "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/${AMASS_ARCHIVE}" && \
    echo "${AMASS_SHA256}  /tmp/${AMASS_ARCHIVE}" | sha256sum --check && \
    tar -xzf "/tmp/${AMASS_ARCHIVE}" -C /tmp && \
    mv "/tmp/${AMASS_DIR}/amass" /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf "/tmp/${SUBFINDER_ARCHIVE}" /tmp/subfinder "/tmp/${AMASS_ARCHIVE}" "/tmp/${AMASS_DIR}" && \
    # Clean apt cache
    apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \
    # Install Python packages
    pip install --no-cache-dir -r requirements.txt && \
    # Prepare Playwright browsers directory (persist across cleanup)
    mkdir -p "$PLAYWRIGHT_BROWSERS_PATH" && chmod -R 0755 "$PLAYWRIGHT_BROWSERS_PATH" && \
    # Install Playwright browser
    playwright install chromium && \
    # Install system deps for Playwright
    apt-get update && \
    playwright install-deps chromium && \
    # Final aggressive cleanup
    apt-get purge -y wget unzip && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf \
        /var/lib/apt/lists/* \
        /var/cache/apt/* \
        /tmp/* \
        /var/tmp/* \
        /root/.cache \
        /usr/share/doc \
        /usr/share/man \
        /usr/share/locale

# Copy application files
COPY . .

# Create directory for logs
RUN mkdir -p /app/logs

# Expose port 5002
EXPOSE 5002

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=5002
# Inside the container the app must listen on all interfaces to be reachable
# through the published port mapping. The host (`python app.py`) defaults to
# loopback; this opt-in is container-only.
ENV KEYLEAK_HOST=0.0.0.0

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5002', timeout=5)"

# Run the application
CMD ["python", "app.py"]
