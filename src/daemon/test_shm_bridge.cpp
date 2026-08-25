// SPDX-License-Identifier: GPL-2.0
/*
 * test_shm_bridge.cpp - do the daemon and UCLIENT actually see the same
 * memory?
 *
 * The claim being tested is the one the whole fast path rests on: a daemon
 * that is NOT running under bpftime's syscall interception can still read and
 * write the maps a bpftime-loaded UCLIENT uses. If that does not hold, every
 * local cache hit has to go through the daemon over the mini-protocol, and
 * the in-process fast path does not exist.
 *
 * Run order:
 *   1. bpftime load ./shm_owner      creates stmts_map and payload_chunks
 *   2. ./test_shm_bridge             attaches from outside and round-trips
 *
 * The daemon here deliberately does NOT run under `bpftime load`, because in
 * production it also owns KCLIENT's real kernel sockmap -- and having its
 * bpf() syscalls intercepted would break the redirect.
 */
#include "shm_bridge.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace qcd;

static int g_fail;

#define CHECK(cond, msg)                                                          \
	do {                                                                      \
		if (!(cond)) {                                                    \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,   \
				msg);                                             \
			g_fail++;                                                 \
		}                                                                 \
	} while (0)

int main()
{
	ShmBridge bridge;

	if (!bridge.open()) {
		fprintf(stderr,
			"SKIP: no bpftime segment with stmts_map/payload_chunks.\n"
			"      Start the owner first:  bpftime load ./build/shm_owner\n");
		return 77;
	}

	CHECK(bridge.available(), "maps discovered by name");

	const std::string sql = "SELECT sku FROM products WHERE stock = 0";

	/* A payload deliberately larger than one chunk, so the multi-chunk
	 * path is exercised rather than the trivial single-chunk case. */
	std::vector<uint8_t> payload;
	for (size_t i = 0; i < kChunkSize + 1234; i++) {
		payload.push_back((uint8_t)(i & 0xFF));
	}

	CHECK(bridge.publish(sql, payload, 60), "published multi-chunk payload");

	StmtRecord rec {};

	CHECK(bridge.lookup(sql, rec), "record readable after publish");
	CHECK(rec.state == STMT_S_LOCAL, "state is LOCAL");
	CHECK(rec.length == payload.size(), "length round-tripped");
	CHECK(rec.chunk_count == 2, "spans two chunks");

	/* Single-flight: the first claim wins, a second must not. */
	const std::string other = "SELECT COUNT(*) FROM products";

	CHECK(bridge.claimPending(other), "first claim wins the fetch");
	CHECK(!bridge.claimPending(other), "second claim is refused while PENDING");

	StmtRecord pend {};

	CHECK(bridge.lookup(other, pend), "pending record readable");
	CHECK(pend.state == STMT_S_PENDING, "state is PENDING");

	/* Publishing over a PENDING record releases the wait. */
	std::vector<uint8_t> small(16, 0xAB);

	CHECK(bridge.publish(other, small, 30), "publish over PENDING");
	CHECK(bridge.lookup(other, pend), "record still readable");
	CHECK(pend.state == STMT_S_LOCAL, "PENDING resolved to LOCAL");

	CHECK(bridge.markError(sql, 5), "error state settable");
	CHECK(bridge.lookup(sql, rec) && rec.state == STMT_S_ERROR, "state is ERROR");

	printf("%s (chunks used: %zu)\n",
	       g_fail == 0 ? "shm bridge: PASS" : "shm bridge: FAIL",
	       bridge.chunksUsed());
	return g_fail == 0 ? 0 : 1;
}
