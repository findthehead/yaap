# Multi-stage build for optimal image size and security

# Stage 1: Builder
FROM python:3.14.2-slim as builder

# Install build dependencies and CLI tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
RUN curl -sSL https://astral.sh/uv/install.sh | sh

# Set environment
ENV PATH="/root/.local/bin:$PATH"

# Stage 2: Runtime
FROM python:3.14.2-slim

LABEL maintainer="YAAP Contributors"
LABEL description="YAAP - Yet Another AI Pentester (Headless Web Security Testing Framework)"
LABEL version="1.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlmap \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install uv from builder
COPY --from=builder /root/.local/bin/uv /usr/local/bin/uv

# Create app directory
WORKDIR /yaap

# Copy YAAP project files
COPY pyproject.toml uv.lock* ./
COPY yaap.py ./
COPY builder.py ./
COPY agents/ ./agents/
COPY tools/ ./tools/
COPY states/ ./states/
COPY utils/ ./utils/
COPY configs/ ./configs/
COPY prompts/ ./prompts/
COPY tests/ ./tests/
COPY README.md LICENSE ./

# Create non-root user for security
RUN useradd -m -u 1000 yaap && \
    chown -R yaap:yaap /yaap

# Switch to non-root user
USER yaap

# Install Python dependencies
RUN uv sync --no-dev

# Create output directory
RUN mkdir -p /yaap/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/yaap/.venv/bin:$PATH"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD uv run python -c "from builder import tools; print(f'OK: {len(tools)} tools')" || exit 1

# Default command - Show help
CMD ["uv", "run", "yaap.py", "--help"]

# Example usage documentation
# docker build -t yaap:latest .
# docker run --rm -e ANTHROPIC_API_KEY=sk-ant-... yaap:latest uv run yaap.py -M claude-3-5-sonnet-20241022 -H http://target.com -P anthropic -T hunt
