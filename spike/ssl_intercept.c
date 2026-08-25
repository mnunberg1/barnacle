// SPDX-License-Identifier: GPL-2.0
/*
 * ssl_intercept.c - Phase 1 spike. Validates the three assumptions the whole
 * transparent-cache architecture rests on, using LD_PRELOAD rather than
 * bpftime.
 *
 * Why LD_PRELOAD for a design that will ship on bpftime: the uncertain part
 * is NOT whether a function can be hooked (bpftime/Frida-gum can hook
 * strictly more than LD_PRELOAD can). It is whether OpenSSL and a real MySQL
 * client BEHAVE correctly when we do the three things the design requires:
 *
 *   1. Suppress an outgoing query at SSL_write -- the client believes it sent
 *      a query that never reached the server.
 *   2. Return EINTR from read()/recv() so nothing ever blocks waiting for a
 *      response that is never coming. OpenSSL must treat this as a retryable
 *      condition (SSL_ERROR_WANT_READ) and NOT tear down the session.
 *   3. Overwrite SSL_read's output buffer and return value, so the client
 *      receives bytes that never travelled over the wire.
 *
 * If all three hold here, they hold under bpftime. If any fails, the
 * architecture needs rethinking -- which is the entire point of running this
 * before building on it.
 *
 * Two modes, selected by SPIKE_MODE:
 *
 *   capture -- run the target query for real, dump the server's plaintext
 *              response (as seen at SSL_read) to SPIKE_FILE.
 *   replay  -- suppress the query, inject the previously captured bytes.
 *
 * Using a real captured response rather than a hand-built one deliberately
 * also exercises replay fidelity: sequence IDs, result-set framing, and the
 * trailing OK/EOF all have to be accepted by the client verbatim. MySQL
 * resets the packet sequence id per command, so replaying a response for the
 * same query at the same point in the command cycle should line up -- and if
 * it does not, that is exactly the E1/E2 problem showing up early, which is
 * worth knowing now.
 *
 * Build:  see spike/Makefile
 * Run:    SPIKE_MODE=capture LD_PRELOAD=./libspike.so <client>
 *         SPIKE_MODE=replay  LD_PRELOAD=./libspike.so <client>
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Opaque -- we never dereference an SSL*, we only pass it through. This
 * avoids needing OpenSSL headers at build time and keeps the shim
 * ABI-agnostic. */
typedef struct ssl_st SSL;

static int (*real_SSL_write)(SSL *, const void *, int);
static int (*real_SSL_read)(SSL *, void *, int);
/* The _ex variants are NOT redundant. Discovered while running this spike:
 * the mysql CLI imports SSL_read/SSL_write, but CPython's _ssl module imports
 * only SSL_read_ex/SSL_write_ex. Hooking one family alone silently misses
 * entire classes of client -- notably every Python driver. Both must be
 * covered. They differ in signature: the _ex forms return 1/0 for
 * success/failure and report the byte count through an out-parameter. */
static int (*real_SSL_write_ex)(SSL *, const void *, size_t, size_t *);
static int (*real_SSL_read_ex)(SSL *, void *, size_t, size_t *);
static ssize_t (*real_read)(int, void *, size_t);
static ssize_t (*real_recv)(int, void *, size_t, int);

#define COM_QUERY 0x03
#define MAX_CAPTURE (1 << 20) /* 1 MiB, matches the design's default cap */

static const char *target_query;   /* SPIKE_QUERY */
static const char *spike_file;     /* SPIKE_FILE */
static int replay_mode;            /* SPIKE_MODE=replay */
static int verbose;                /* SPIKE_VERBOSE */

/* Per-thread, because MySQL connections are per-thread in the clients we
 * care about and the real implementation will key this off the connection.
 * `armed` means: we suppressed a query on this thread and owe the caller a
 * fabricated response. */
static __thread int armed;
static __thread int capture_pending; /* capture mode: next SSL_read is ours */

static unsigned char inject_buf[MAX_CAPTURE];
static size_t inject_len;

static void log_msg(const char *fmt, ...)
{
	va_list ap;

	if (!verbose) {
		return;
	}
	fprintf(stderr, "[spike] ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void init(void)
{
	static int done;

	if (done) {
		return;
	}
	done = 1;

	/* Only the libc symbols are resolved eagerly. The OpenSSL ones are
	 * resolved lazily at first use -- see resolve() below. */
	real_read = dlsym(RTLD_NEXT, "read");
	real_recv = dlsym(RTLD_NEXT, "recv");

	target_query = getenv("SPIKE_QUERY");
	spike_file = getenv("SPIKE_FILE");
	verbose = getenv("SPIKE_VERBOSE") != NULL;
	{
		const char *mode = getenv("SPIKE_MODE");

		replay_mode = mode && strcmp(mode, "replay") == 0;
	}

	if (!target_query) {
		target_query = "SELECT * FROM products WHERE stock = 0";
	}
	if (!spike_file) {
		spike_file = "/tmp/spike_capture.bin";
	}

	if (replay_mode) {
		FILE *f = fopen(spike_file, "rb");

		if (f) {
			inject_len = fread(inject_buf, 1, sizeof(inject_buf), f);
			fclose(f);
			log_msg("replay mode: loaded %zu bytes from %s", inject_len,
				spike_file);
		} else {
			fprintf(stderr,
				"[spike] FATAL: replay mode but cannot open %s: %s\n",
				spike_file, strerror(errno));
		}
	} else {
		log_msg("capture mode: will dump to %s", spike_file);
	}
	log_msg("target query: %s", target_query);
}

/* Resolve an OpenSSL symbol lazily, on first use.
 *
 * This is NOT premature generality -- it is a bug fix, and the underlying
 * constraint applies to the real bpftime implementation too. init() first
 * runs on whatever call we intercept earliest, which for a Python process is
 * a read() during interpreter startup -- long before `import ssl` dlopen()s
 * _ssl.so and pulls in libssl. Resolving SSL_* eagerly at that moment yields
 * NULL for every one of them, and the NULL is then cached forever; the first
 * real SSL_read_ex() call segfaults.
 *
 * Any TLS library that arrives via dlopen() has this property. The design's
 * UCLIENT must therefore be able to attach to libssl when it appears, not
 * only at process start. */
static void *resolve(void **slot, const char *name)
{
	static void *libssl_handle;

	if (*slot) {
		return *slot;
	}

	*slot = dlsym(RTLD_NEXT, name);
	if (*slot) {
		return *slot;
	}

	/* RTLD_NEXT came up empty. Second real finding from this spike:
	 * CPython dlopen()s _ssl.so with RTLD_LOCAL, so libssl.so.3 lands in a
	 * PRIVATE namespace that RTLD_NEXT does not search. Our interposition
	 * still works -- calls from _ssl.so bind against the global scope
	 * first, which is where an LD_PRELOAD object lives -- but reaching the
	 * genuine function behind our hook needs an explicit handle.
	 *
	 * RTLD_NOLOAD returns a handle only if the library is already mapped,
	 * so this never causes a load of its own; it just gives us a scope to
	 * search that RTLD_NEXT cannot reach.
	 *
	 * Note this asymmetry is an LD_PRELOAD limitation specifically.
	 * bpftime/Frida-gum patch by ADDRESS rather than through the dynamic
	 * linker, so they are not subject to it -- meaning the real
	 * implementation should handle this case more easily than the spike
	 * does, not less. */
	if (!libssl_handle) {
		libssl_handle = dlopen("libssl.so.3", RTLD_NOW | RTLD_NOLOAD);
		if (!libssl_handle) {
			libssl_handle = dlopen("libssl.so", RTLD_NOW | RTLD_NOLOAD);
		}
	}
	if (libssl_handle) {
		*slot = dlsym(libssl_handle, name);
	}

	if (!*slot) {
		fprintf(stderr, "[spike] FATAL: cannot resolve %s\n", name);
		abort();
	}
	return *slot;
}

/* Is this buffer a COM_QUERY packet whose text matches our target?
 * Layout: [3-byte payload len][1-byte seq][0x03][query text...] */
static int is_target_query(const unsigned char *buf, int len)
{
	size_t qlen;
	int tlen;

	if (len < 5 || buf[4] != COM_QUERY) {
		return 0;
	}
	qlen = strlen(target_query);
	tlen = len - 5;
	if ((size_t)tlen != qlen) {
		return 0;
	}
	return memcmp(buf + 5, target_query, qlen) == 0;
}

/* Shared by SSL_write and SSL_write_ex. Returns 1 if the caller should
 * suppress the real write (replay mode, target query matched). */
static int note_write(const void *buf, size_t num)
{
	if (!is_target_query(buf, (int)num)) {
		return 0;
	}
	if (replay_mode) {
		/* ASSUMPTION 1: suppress. Report full success to the caller;
		 * the query never reaches the server. */
		armed = 1;
		log_msg("write: SUPPRESSED target query (%zu bytes), reporting "
			"success to caller",
			num);
		return 1;
	}
	capture_pending = 1;
	log_msg("write: saw target query (%zu bytes), will capture its response",
		num);
	return 0;
}

/* Shared by SSL_read and SSL_read_ex. Returns the number of injected bytes,
 * or 0 if nothing was injected. */
static int maybe_inject(void *buf, size_t num)
{
	int n;

	if (!armed) {
		return 0;
	}
	n = (int)inject_len;
	if ((size_t)n > num) {
		n = (int)num;
	}
	armed = 0;
	if (n <= 0) {
		log_msg("read: armed but nothing to inject!");
		return 0;
	}
	memcpy(buf, inject_buf, (size_t)n);
	log_msg("read: INJECTING %d bytes", n);
	return n;
}

static void maybe_capture(const void *buf, size_t len)
{
	FILE *f;

	if (!capture_pending || len == 0) {
		return;
	}
	capture_pending = 0;
	f = fopen(spike_file, "wb");
	if (!f) {
		fprintf(stderr, "[spike] cannot write %s: %s\n", spike_file,
			strerror(errno));
		return;
	}
	fwrite(buf, 1, len, f);
	fclose(f);
	log_msg("read: CAPTURED %zu bytes to %s", len, spike_file);
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
	init();

	if (note_write(buf, (size_t)num)) {
		return num;
	}
	resolve((void **)&real_SSL_write, "SSL_write");
	return real_SSL_write(ssl, buf, num);
}

int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
{
	init();

	if (note_write(buf, num)) {
		if (written) {
			*written = num;
		}
		return 1; /* success */
	}
	resolve((void **)&real_SSL_write_ex, "SSL_write_ex");
	return real_SSL_write_ex(ssl, buf, num, written);
}

/* ASSUMPTION 2: while armed, never block and never let the TLS record layer
 * see anything. EINTR is chosen over EAGAIN because it is legal on both
 * blocking and non-blocking fds, whereas EAGAIN nominally cannot occur on a
 * blocking fd and some client code treats it as fatal there. */
ssize_t read(int fd, void *buf, size_t count)
{
	init();

	if (armed) {
		log_msg("read(fd=%d): returning EINTR while armed", fd);
		errno = EINTR;
		return -1;
	}
	return real_read(fd, buf, count);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	init();

	if (armed) {
		log_msg("recv(fd=%d): returning EINTR while armed", sockfd);
		errno = EINTR;
		return -1;
	}
	return real_recv(sockfd, buf, len, flags);
}

/* ASSUMPTION 3: override the output buffer and return value. Both variants
 * call the real function first so OpenSSL's own state machine runs exactly as
 * it normally would -- it will hit our EINTR, conclude SSL_ERROR_WANT_READ,
 * and return without altering session state. Only then do we substitute our
 * own bytes. */
int SSL_read(SSL *ssl, void *buf, int num)
{
	int ret, injected;

	init();

	resolve((void **)&real_SSL_read, "SSL_read");
	ret = real_SSL_read(ssl, buf, num);

	injected = maybe_inject(buf, (size_t)num);
	if (injected > 0) {
		log_msg("SSL_read: real returned %d, injected %d instead", ret,
			injected);
		return injected;
	}
	if (ret > 0) {
		maybe_capture(buf, (size_t)ret);
	}
	return ret;
}

int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
{
	int ret, injected;

	init();

	resolve((void **)&real_SSL_read_ex, "SSL_read_ex");
	ret = real_SSL_read_ex(ssl, buf, num, readbytes);

	injected = maybe_inject(buf, num);
	if (injected > 0) {
		log_msg("SSL_read_ex: real returned %d, injected %d instead", ret,
			injected);
		if (readbytes) {
			*readbytes = (size_t)injected;
		}
		return 1; /* success */
	}
	if (ret == 1 && readbytes && *readbytes > 0) {
		maybe_capture(buf, *readbytes);
	}
	return ret;
}
