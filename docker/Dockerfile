# Linux environment to build and exercise the namespace sandbox (abx_init).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev python3 python3-pytest ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /work
# Source is bind-mounted at run time (docker/run.sh); the entrypoint delegates a cgroup parent.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
