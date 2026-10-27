# Linux environment to build and exercise the namespace sandbox (abx_init).
# The dev host is macOS/arm64; namespaces/pivot_root are Linux-only, so the real
# sandbox is built and run here (Docker Desktop's aarch64 VM).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev python3 python3-pytest ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /work
# The source is bind-mounted at run time (see docker/run.sh). The entrypoint sets
# up a delegated cgroup parent (best-effort) before running the command.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
