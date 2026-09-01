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
        xz-utils \
        libgtest-dev \
        libgmock-dev \
        default-mysql-client \
        libmariadb-dev \
        redis-tools \
        iproute2 \
        procps \
        less \
        ca-certificates \
        curl \
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

# Frida devkits: a static lib and a header, no build step. Used for the
# userspace agent and its injector. eBPF covers the kernel side only.
ARG FRIDA_VERSION=17.2.11
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in arm64) fa=arm64 ;; amd64) fa=x86_64 ;; *) echo "unsupported $arch" >&2; exit 1 ;; esac; \
    mkdir -p /opt/frida; \
    for kit in gum core; do \
        url="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-${kit}-devkit-${FRIDA_VERSION}-linux-${fa}.tar.xz"; \
        curl -fsSL "$url" -o /tmp/frida.tar.xz; \
        tar -xJf /tmp/frida.tar.xz -C /opt/frida; \
        rm -f /tmp/frida.tar.xz; \
    done

WORKDIR /workspace
CMD ["sleep", "infinity"]
