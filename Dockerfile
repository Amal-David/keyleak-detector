# Use Python 3.11 on Debian Bookworm (stable) for reliable apt repos
FROM python:3.11-slim-bookworm

# Tool versions
ARG TARGETARCH
ARG SUBFINDER_VERSION=2.12.0
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
    wget -qO "/tmp/${SUBFINDER_ARCHIVE}" "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/${SUBFINDER_ARCHIVE}" && \
    wget -qO /tmp/subfinder_checksums.txt "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_checksums.txt" && \
    grep -E "[[:space:]]${SUBFINDER_ARCHIVE}$" /tmp/subfinder_checksums.txt | (cd /tmp && sha256sum -c -) && \
    mkdir -p /tmp/subfinder && \
    unzip -q "/tmp/${SUBFINDER_ARCHIVE}" -d /tmp/subfinder && \
    mv /tmp/subfinder/subfinder /usr/local/bin/subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    wget -qO "/tmp/${AMASS_ARCHIVE}" "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/${AMASS_ARCHIVE}" && \
    wget -qO /tmp/amass_checksums.txt "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_checksums.txt" && \
    grep -E "[[:space:]]${AMASS_ARCHIVE}$" /tmp/amass_checksums.txt | (cd /tmp && sha256sum -c -) && \
    tar -xzf "/tmp/${AMASS_ARCHIVE}" -C /tmp && \
    mv "/tmp/${AMASS_DIR}/amass" /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf "/tmp/${SUBFINDER_ARCHIVE}" /tmp/subfinder /tmp/subfinder_checksums.txt "/tmp/${AMASS_ARCHIVE}" "/tmp/${AMASS_DIR}" /tmp/amass_checksums.txt && \
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

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5002', timeout=5)"

# Run the application
CMD ["python", "app.py"]
