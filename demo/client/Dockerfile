# The client application's image.
#
# Deliberately not the bpf container's image. The point of the demo is that
# the cache attaches to a program that was built and shipped without knowing
# it exists, so the application gets an image with an application's contents:
# a Python runtime, a MySQL driver, and nothing belonging to this project. No
# clang, no libbpf, no frida, and no source tree.
#
# Debian trixie for the same reason the bpf image uses it -- the same OpenSSL
# (libssl.so.3), which is what the agent hooks. The mysqlclient driver is a C
# extension over libmariadb, which does its TLS through that shared library
# rather than in-process, so there is something to hook. A driver that spoke
# TLS itself (Go's crypto/tls, Java's JSSE) would not be attachable at all,
# and barnacle says so rather than attaching and doing nothing.

# --- build the driver -----------------------------------------------------
#
# mysqlclient is a C extension with no prebuilt wheel for this platform, so it
# needs a compiler. Two stages so the compiler does not end up in the image
# that runs: a toolchain sitting in the application container would make the
# demo's claim -- that this is an ordinary sealed application -- less true
# than it should be.
FROM debian:trixie-slim AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-dev \
        gcc libc6-dev pkg-config libmariadb-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN pip install --no-cache-dir mysqlclient==2.2.8

# --- the application ------------------------------------------------------
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 libmariadb3 openssl procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY app.py /app/app.py

# Unbuffered, so the log this container writes is the log you see in the
# terminal following it, with no delay between a query finishing and its line
# appearing.
ENV PYTHONUNBUFFERED=1
WORKDIR /app
CMD ["python3", "/app/app.py"]
