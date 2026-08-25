// SPDX-License-Identifier: GPL-2.0
/*
 * shm_bridge.h - the daemon's window into UCLIENT's memory.
 *
 * UCLIENT runs as a bpftime program inside each client process; the daemon is
 * a separate process. They share state through bpftime's shared-memory maps.
 *
 * --- why the daemon can reach them at all --------------------------------
 *
 * A process started under `bpftime load` has its bpf() syscalls intercepted
 * and redirected into shared memory. The daemon cannot run that way, because
 * it also owns KCLIENT's *real* kernel sockmap -- intercepting those calls
 * would break the redirect entirely.
 *
 * bpftime_initialize_global_shm(SHM_OPEN_ONLY) sidesteps that: it is a
 * library call that maps the existing segment directly, not a bpf() syscall.
 * So the daemon holds genuine kernel BPF fds *and* reads and writes bpftime's
 * userspace maps. This is the same door `bpftimetool` uses from outside.
 *
 * --- why the payload arena is a map, not a raw mmap ----------------------
 *
 * A raw shared mapping lands at a different address in every process, and the
 * UCLIENT program is shared across all of them -- it has nowhere to keep a
 * per-process base address. Storing payloads in a chunked BPF array map
 * removes the problem: bpf_map_lookup_elem() returns a pointer valid in
 * whichever process calls it, so UCLIENT addresses bytes by chunk index and
 * never needs to know where the daemon mapped anything.
 *
 * --- what lives where ----------------------------------------------------
 *
 *   bpftime shm    stmts_map, payload_chunks     the fast path: a local hit
 *                                                is answered in-process with
 *                                                no syscall and no daemon
 *   kernel BPF     sock_map, pipe_pairs          the redirect
 *   mini-protocol  over the redirected socket    the wakeup and slow path
 */
#ifndef VALKEY_EBPF_DAEMON_SHM_BRIDGE_H
#define VALKEY_EBPF_DAEMON_SHM_BRIDGE_H

#include <cstdint>
#include <string>
#include <vector>

namespace qcd {

/* Must match the UCLIENT program's definitions exactly. */
constexpr uint32_t kStmtTextMax = 512;
constexpr uint32_t kChunkSize = 4096;

enum StmtState : uint32_t {
	STMT_S_EMPTY = 0,
	STMT_S_LOCAL = 1,   /* payload present; answer in-process */
	STMT_S_PENDING = 2, /* someone is fetching; wait */
	STMT_S_ERROR = 3,   /* cache unusable; pass through */
};

/* One entry in stmts_map. Payload bytes are NOT stored inline -- they live in
 * payload_chunks, referenced by index. Keeping this record small matters
 * because UCLIENT touches it on every intercepted statement. */
struct StmtRecord {
	uint64_t ts_ns;      /* when the payload was published */
	uint32_t state;      /* enum StmtState, moved by atomic CAS */
	uint32_t chunk;      /* first chunk index in payload_chunks */
	uint32_t chunk_count;
	uint32_t length;     /* payload bytes across those chunks */
	uint32_t ttl_secs;
	uint32_t _pad;
};

struct StmtKey {
	char text[kStmtTextMax];
};

/* Opens bpftime's shm read/write and locates the maps UCLIENT created.
 *
 * Maps are addressed by an index into the shm handler table rather than by
 * name, so the indices are discovered by enumerating handlers and matching
 * bpf_map_handler::name -- hardcoding them would break the moment UCLIENT's
 * load order changed.
 */
class ShmBridge {
public:
	/* Returns false when no bpftime segment exists yet, i.e. UCLIENT has
	 * not been loaded. The daemon stays useful without it -- everything
	 * still works over the mini-protocol, just without the in-process fast
	 * path. */
	bool open();

	bool available() const
	{
		return stmts_fd_ >= 0 && chunks_fd_ >= 0;
	}

	/* Publish a response so UCLIENT can serve it without involving the
	 * daemon at all.
	 *
	 * Writes the payload chunks FIRST, then flips the record to
	 * STMT_S_LOCAL. Order matters: a reader that sees LOCAL must be
	 * guaranteed the bytes behind it are already there. The record is
	 * never mutated in place afterwards, so readers need no lock. */
	bool publish(const std::string &sql, const std::vector<uint8_t> &payload,
		      uint32_t ttl_secs);

	/* Mark a statement as being fetched, so concurrent clients wait rather
	 * than each hitting the database. Returns true if this caller won the
	 * race and owns the fetch. */
	bool claimPending(const std::string &sql);

	bool markError(const std::string &sql, uint32_t ttl_secs);

	bool lookup(const std::string &sql, StmtRecord &out);

	/* Chunks are never freed individually -- the arena is a bump allocator
	 * that wraps. Responses are short-lived under a TTL, and a wrapped
	 * chunk is only reachable through a record that has already been
	 * superseded. */
	size_t chunksUsed() const
	{
		return next_chunk_;
	}

private:
	bool writeChunks(const std::vector<uint8_t> &payload, uint32_t &first_chunk,
			  uint32_t &count);

	int stmts_fd_ = -1;
	int chunks_fd_ = -1;
	uint32_t max_chunks_ = 0;
	uint32_t next_chunk_ = 0;
};

/* Build the fixed-width key UCLIENT hashes on. Statements longer than the
 * limit are not cacheable; UCLIENT cannot key them either. */
bool makeStmtKey(const std::string &sql, StmtKey &out);

} // namespace qcd

#endif /* VALKEY_EBPF_DAEMON_SHM_BRIDGE_H */
