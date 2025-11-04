# Use Python 3.11 on Debian Bookworm (stable) for reliable apt repos
FROM python:3.11-slim-bookworm

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
    apt-get install -y --no-install-recommends wget ca-certificates && \
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
    apt-get purge -y wget && \
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
