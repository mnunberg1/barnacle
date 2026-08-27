// SPDX-License-Identifier: GPL-2.0
#include "agent/arena.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

namespace qcd {

bool Arena::open(int map_fd)
{
	size_t len = (size_t)QC_ARENA_PAGES * 4096;

	if (map_fd < 0) {
		return false;
	}

	/*
	 * MAP_FIXED, deliberately.
	 *
	 * The arena has to land at the same address in every process or the
	 * pointers stored in it mean nothing outside whoever wrote them. Asking
	 * for a hint and accepting whatever we get would appear to work in the
	 * daemon and then hand clients garbage, which is the worst possible
	 * failure mode -- so if this address is unavailable, fail loudly here.
	 */
	void *p = mmap((void *)QC_ARENA_VA, len, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_FIXED, map_fd, 0);

	if (p == MAP_FAILED) {
		fprintf(stderr, "arena: cannot map %zu bytes at %#llx: %s\n", len,
			(unsigned long long)QC_ARENA_VA, strerror(errno));
		return false;
	}

	base = (uint8_t *)p;
	cap = len;
	next = 0;
	nwrap = 0;
	return true;
}

void Arena::close()
{
	if (base) {
		munmap(base, cap);
		base = nullptr;
		cap = 0;
	}
}

void *Arena::alloc(size_t n)
{
	if (!base || n == 0 || n > cap) {
		return nullptr;
	}

	size_t need = (n + 7) & ~(size_t)7;

	if (next + need > cap) {
		next = 0;
		nwrap++;
	}

	void *p = base + next;

	next += need;
	return p;
}

void *Arena::put(const void *src, size_t n)
{
	void *p = alloc(n);

	if (!p) {
		return nullptr;
	}
	std::memcpy(p, src, n);
	return p;
}

} // namespace qcd
