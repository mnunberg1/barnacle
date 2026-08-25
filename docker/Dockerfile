# Toolchain for building and running CO-RE eBPF programs, plus the clients
# needed to drive the demo (MySQL and Valkey).
#
# Debian trixie rather than Ubuntu 24.04: Ubuntu has no `bpftool` binary
# package on arm64, while trixie ships bpftool 7.5 built from the 6.12 tree --
# the same kernel series Docker Desktop's LinuxKit VM runs.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        bpftool \
        libelf-dev \
        zlib1g-dev \
        gcc \
        g++ \
        make \
        pkg-config \
        python3 \
        python3-venv \
        python3-dev \
        default-mysql-client \
        libmariadb-dev \
        redis-tools \
        iproute2 \
        procps \
        less \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Debian marks the system Python as externally managed, so the demo helpers
# get their own venv rather than fighting with pip.
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
# Several MySQL drivers, deliberately: the cache hooks the shared TLS library
# rather than any driver's internals, so pure-Python clients (PyMySQL) and C
# extensions (mysqlclient) are both observable and both worth demonstrating.
RUN pip install --no-cache-dir PyMySQL==1.1.1 redis==5.2.1 \
        mysqlclient==2.2.8 Flask==3.1.0

WORKDIR /workspace
CMD ["sleep", "infinity"]
