# HydraSight orchestrator image.
#
# Deliberately contains NO offensive tooling: all commands execute against the
# separate kali-server-mcp bridge (see docker-compose.yml). The console runs as
# a non-root user.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install the package (pulls in runtime deps only).
COPY pyproject.toml README.md ./
COPY hydrasight ./hydrasight
RUN pip install --no-cache-dir .

# Non-root console user.
RUN useradd --create-home --uid 1000 hydra \
    && mkdir -p /app/hydrasight_output \
    && chown -R hydra:hydra /app
USER hydra

ENTRYPOINT ["hydrasight"]
CMD ["--help"]
