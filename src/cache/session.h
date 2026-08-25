// SPDX-License-Identifier: GPL-2.0
/*
 * session.h - per-connection MySQL response tracking and cache decisions.
 *
 * A cached response is only useful if we know where it ends, and only *safe*
 * if we know the server was not mid-transaction when it was produced. Both
 * facts come from walking the response, which is what this state machine
 * does.
 *
 * Response shapes after a COM_QUERY:
 *
 *   OK / ERR              single message, done
 *   LOCAL INFILE          out of scope, never cached
 *   result set            column count, N column definitions, [EOF],
 *                         rows..., terminated by EOF or -- when
 *                         CLIENT_DEPRECATE_EOF is negotiated -- an OK packet
 *                         wearing an 0xFE header
 *
 * The CLIENT_DEPRECATE_EOF branch is the reason capabilities have to be
 * captured from the handshake rather than assumed: the same bytes mean
 * different things depending on what the two sides agreed to.
 */
#ifndef VALKEY_EBPF_CACHE_SESSION_H
#define VALKEY_EBPF_CACHE_SESSION_H

#include "../mysql/protocol.h"

#include <cstdint>
#include <string>
#include <vector>

namespace cache {

class ResponseTracker {
public:
	void begin(uint32_t caps);

	/* Feed one reassembled response message. Returns true once the whole
	 * response has been seen. */
	bool feed(const mysql::Message &msg);

	bool complete() const
	{
		return state_ == State::Done;
	}

	/* True if anything about this response makes it unsafe or pointless
	 * to cache: an error, a LOCAL INFILE request, multiple result sets,
	 * or an open transaction. */
	bool poisoned() const
	{
		return poisoned_;
	}

	/* Transaction state reported by the final OK/EOF packet. */
	bool inTransaction() const
	{
		return in_transaction_;
	}

private:
	enum class State { Init, ColumnDefs, ColumnEof, Rows, Done };

	void finish(const mysql::Message &msg);

	State state_ = State::Init;
	uint32_t caps_ = 0;
	uint64_t columns_left_ = 0;
	bool poisoned_ = false;
	bool in_transaction_ = false;
};

/*
 * Everything tracked for one client connection.
 *
 * `caps` is the negotiated capability set, learned by watching the plaintext
 * handshake before TLS is established. Once the connection upgrades we can no
 * longer see the wire, but by then we already have what we need -- which is
 * precisely why the handshake is worth parsing rather than skipping.
 */
struct Connection {
	uint32_t server_caps = 0;
	uint32_t caps = 0;
	bool handshake_done = false;
	bool tls = false;

	/* Set once a transaction is observed; caching stays disabled until it
	 * ends. Reads inside a transaction may see uncommitted data, and
	 * caching them would leak one session's view into others. */
	bool in_transaction = false;

	/* A response is outstanding for this connection.
	 *
	 * Set for EVERY statement, not only cacheable ones. Transaction state
	 * arrives on the response to whatever opened the transaction --
	 * typically `START TRANSACTION`, which is not itself cacheable -- so a
	 * tracker that only ran for cacheable statements would never see the
	 * IN_TRANS flag and would happily cache reads inside a transaction.
	 * That is a correctness bug, not an optimization gap: those reads can
	 * observe uncommitted state private to one session. */
	bool awaiting_response = false;

	/* The statement in flight, set only when it is one we intend to cache. */
	std::string pending_query;
	bool capturing = false;

	mysql::MessageReader response_reader;
	ResponseTracker tracker;

	/* Raw response bytes accumulated for a cacheable statement. Stored
	 * verbatim: MySQL resets the sequence id per command, so a response
	 * captured at the start of one command replays correctly at the start
	 * of another, after renumbering. */
	std::vector<uint8_t> captured;

	void reset()
	{
		awaiting_response = false;
		pending_query.clear();
		capturing = false;
		captured.clear();
		response_reader.reset();
	}
};

} // namespace cache

#endif /* VALKEY_EBPF_CACHE_SESSION_H */
