# Phase 1 spike. Run inside the bpf container:
#   docker compose exec bpf make -C spike
#
# Validates the three assumptions the transparent-cache architecture rests on
# before any of it is built. See ssl_intercept.c's header comment.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -fPIC
LDFLAGS := -shared -ldl

.PHONY: all clean capture replay

all: libspike.so

libspike.so: ssl_intercept.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm -f libspike.so /tmp/spike_capture.bin
