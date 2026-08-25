// SPDX-License-Identifier: GPL-2.0
#include "shm_bridge.h"

#include <cstdio>
#include <cstring>
#include <ctime>

/* bpftime's runtime headers. These pull in the shared-memory handler manager,
 * which is what lets a process outside bpftime's syscall interception reach
 * the maps. */
#include <bpftime_shm.hpp>
/* handler_manager and bpf_map_handler are not in the public header. Reaching
 * into the internal one is what bpftimetool does too -- the map-by-name
 * enumeration simply is not exposed publicly. */
#include <bpftime_shm_internal.hpp>

namespace qcd {
namespace {

uint64_t now_ns()
{
	struct timespec ts {};

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Find a map by name by walking the shm handler table.
 *
 * bpftime addresses maps by an index into that table, and the index depends
 * on the order UCLIENT created them. Hardcoding it would silently break the
 * first time a map was added or reordered, so the name is matched instead.
 */
int findMapByName(const char *want)
{
	using namespace bpftime;

	const handler_manager *mgr = shm_holder.global_shared_memory.get_manager();

	if (!mgr) {
		return -1;
	}
	for (size_t i = 0; i < mgr->size(); i++) {
		const auto &h = mgr->get_handler((int)i);

		if (!std::holds_alternative<bpf_map_handler>(h)) {
			continue;
		}
		const auto &m = std::get<bpf_map_handler>(h);

		if (std::strcmp(m.name.c_str(), want) == 0) {
			return (int)i;
		}
	}
	return -1;
}

} // namespace

bool makeStmtKey(const std::string &sql, StmtKey &out)
{
	if (sql.empty() || sql.size() > kStmtTextMax - 1) {
		return false;
	}
	std::memset(&out, 0, sizeof(out));
	std::memcpy(out.text, sql.data(), sql.size());
	return true;
}

bool ShmBridge::open()
{
	try {
		/* SHM_OPEN_ONLY: attach to what UCLIENT already created, never
		 * create it. If the daemon created the segment it would race
		 * UCLIENT's own initialization. */
		bpftime_initialize_global_shm(bpftime::shm_open_type::SHM_OPEN_ONLY);
	} catch (const std::exception &e) {
		fprintf(stderr,
			"daemon: no bpftime segment (%s) -- running without the "
			"in-process fast path\n",
			e.what());
		return false;
	}

	stmts_fd_ = findMapByName("stmts_map");
	chunks_fd_ = findMapByName("payload_chunks");

	if (!available()) {
		fprintf(stderr,
			"daemon: bpftime segment present but stmts_map/payload_chunks "
			"not found -- is UCLIENT loaded?\n");
		return false;
	}

	{
		bpftime::bpf_map_attr attr {};

		if (bpftime_map_get_info(chunks_fd_, &attr, nullptr, nullptr) == 0) {
			max_chunks_ = attr.max_ents;
		}
	}
	if (max_chunks_ == 0) {
		max_chunks_ = 1;
	}

	fprintf(stderr, "daemon: bpftime shm attached (stmts=%d chunks=%d, %u chunks)\n",
		stmts_fd_, chunks_fd_, max_chunks_);
	return true;
}

bool ShmBridge::writeChunks(const std::vector<uint8_t> &payload, uint32_t &first_chunk,
			     uint32_t &count)
{
	uint32_t need = (uint32_t)((payload.size() + kChunkSize - 1) / kChunkSize);

	if (need == 0 || need > max_chunks_) {
		return false;
	}
	/* Bump allocator that wraps. Nothing is freed individually: entries are
	 * short-lived under a TTL, and a wrapped chunk is only reachable
	 * through a record that has already been replaced. */
	if (next_chunk_ + need > max_chunks_) {
		next_chunk_ = 0;
	}
	first_chunk = next_chunk_;
	count = need;

	for (uint32_t i = 0; i < need; i++) {
		uint8_t buf[kChunkSize];
		size_t off = (size_t)i * kChunkSize;
		size_t n = payload.size() - off;

		if (n > kChunkSize) {
			n = kChunkSize;
		}
		std::memset(buf, 0, sizeof(buf));
		std::memcpy(buf, payload.data() + off, n);

		uint32_t key = first_chunk + i;

		if (bpftime_map_update_elem(chunks_fd_, &key, buf, 0) != 0) {
			return false;
		}
	}
	next_chunk_ += need;
	return true;
}

bool ShmBridge::publish(const std::string &sql, const std::vector<uint8_t> &payload,
			 uint32_t ttl_secs)
{
	StmtKey key {};
	StmtRecord rec {};
	uint32_t first = 0, count = 0;

	if (!available() || !makeStmtKey(sql, key) || payload.empty()) {
		return false;
	}

	/* Bytes first, record second. A reader that observes STMT_S_LOCAL must
	 * be able to trust that the chunks behind it are already populated;
	 * publishing the record first would expose a window where UCLIENT
	 * serves uninitialized memory as a query result. */
	if (!writeChunks(payload, first, count)) {
		return false;
	}

	rec.ts_ns = now_ns();
	rec.state = STMT_S_LOCAL;
	rec.chunk = first;
	rec.chunk_count = count;
	rec.length = (uint32_t)payload.size();
	rec.ttl_secs = ttl_secs;

	return bpftime_map_update_elem(stmts_fd_, &key, &rec, 0) == 0;
}

bool ShmBridge::claimPending(const std::string &sql)
{
	StmtKey key {};
	StmtRecord rec {};

	if (!available() || !makeStmtKey(sql, key)) {
		return false;
	}

	const void *existing = bpftime_map_lookup_elem(stmts_fd_, &key);

	if (existing) {
		const StmtRecord *cur = (const StmtRecord *)existing;

		/* Someone else already owns the fetch; the caller should wait
		 * rather than start a second one. */
		if (cur->state == STMT_S_PENDING) {
			return false;
		}
	}

	rec.ts_ns = now_ns();
	rec.state = STMT_S_PENDING;
	return bpftime_map_update_elem(stmts_fd_, &key, &rec, 0) == 0;
}

bool ShmBridge::markError(const std::string &sql, uint32_t ttl_secs)
{
	StmtKey key {};
	StmtRecord rec {};

	if (!available() || !makeStmtKey(sql, key)) {
		return false;
	}
	rec.ts_ns = now_ns();
	rec.state = STMT_S_ERROR;
	rec.ttl_secs = ttl_secs;
	return bpftime_map_update_elem(stmts_fd_, &key, &rec, 0) == 0;
}

bool ShmBridge::lookup(const std::string &sql, StmtRecord &out)
{
	StmtKey key {};

	if (!available() || !makeStmtKey(sql, key)) {
		return false;
	}
	const void *v = bpftime_map_lookup_elem(stmts_fd_, &key);

	if (!v) {
		return false;
	}
	std::memcpy(&out, v, sizeof(out));
	return true;
}

} // namespace qcd
