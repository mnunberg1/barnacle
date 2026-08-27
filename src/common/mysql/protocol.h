// SPDX-License-Identifier: GPL-2.0
/*
 * protocol.h - MySQL client/server protocol framing and parsing.
 *
 * This lives in userspace C++ rather than BPF C on purpose. An earlier
 * incarnation of this project did the equivalent work inside a verifier-
 * constrained BPF program, which forced a long list of compromises: a hard
 * 512-byte statement cap, bounded loops, no multi-packet reassembly, and a
 * *content heuristic* for CLIENT_QUERY_ATTRIBUTES because the negotiated
 * capability flags were not available.
 *
 * Here the capabilities are parsed from the handshake and carried per
 * connection, so query-attribute framing is decoded exactly rather than
 * guessed, statements have no length cap, and the >=16 MiB continuation rule
 * is handled properly.
 *
 * Everything in this header is pure computation over byte buffers: no
 * sockets, no kernel, no root. That makes it unit-testable offline, which is
 * the point -- it is the only part of the system that can be tested without
 * a live database and a privileged container.
 */
#ifndef VALKEY_EBPF_MYSQL_PROTOCOL_H
#define VALKEY_EBPF_MYSQL_PROTOCOL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace mysql {

/* Every packet is a 4-byte header (3-byte little-endian payload length, then
 * a 1-byte sequence id) followed by that many payload bytes. */
constexpr size_t kHeaderLen = 4;

/* A single wire packet cannot carry more than this. A logical message longer
 * than the limit is split: each full-size chunk is emitted as a packet of
 * exactly kMaxPayload bytes, and the sequence is terminated by a packet
 * strictly shorter than it -- which means a message whose length is an exact
 * multiple of kMaxPayload ends with a zero-length packet. */
constexpr uint32_t kMaxPayload = 0xFFFFFF;

/* Capability flags. Only those this project actually reasons about are
 * named; the numeric values are from the MySQL protocol documentation. */
enum Capability : uint32_t {
	CLIENT_LONG_PASSWORD = 0x00000001,
	CLIENT_COMPRESS = 0x00000020,
	CLIENT_PROTOCOL_41 = 0x00000200,
	CLIENT_SSL = 0x00000800,
	CLIENT_TRANSACTIONS = 0x00002000,
	CLIENT_SECURE_CONNECTION = 0x00008000,
	CLIENT_MULTI_STATEMENTS = 0x00010000,
	CLIENT_MULTI_RESULTS = 0x00020000,
	CLIENT_PLUGIN_AUTH = 0x00080000,
	CLIENT_CONNECT_ATTRS = 0x00100000,
	CLIENT_SESSION_TRACK = 0x00800000,
	CLIENT_DEPRECATE_EOF = 0x01000000,
	CLIENT_ZSTD_COMPRESSION_ALGORITHM = 0x04000000,
	CLIENT_QUERY_ATTRIBUTES = 0x08000000,
};

/* Server status flags, carried in OK/EOF packets. IN_TRANS is the one that
 * matters most here: caching must be bypassed while a transaction is open. */
enum ServerStatus : uint16_t {
	SERVER_STATUS_IN_TRANS = 0x0001,
	SERVER_STATUS_AUTOCOMMIT = 0x0002,
	SERVER_MORE_RESULTS_EXISTS = 0x0008,
};

enum Command : uint8_t {
	COM_QUIT = 0x01,
	COM_INIT_DB = 0x02,
	COM_QUERY = 0x03,
	/* No payload beyond the command byte. Worth naming because it is the
	 * clearest example of a packet that must be consumed rather than
	 * skipped: ignoring its bytes would misalign everything after it. */
	COM_PING = 0x0E,
	COM_STMT_PREPARE = 0x16,
	COM_STMT_EXECUTE = 0x17,
	COM_STMT_CLOSE = 0x19,
};

/* One reassembled logical message: continuation packets are already joined,
 * so `payload` is the complete command or response body. */
struct Message {
	std::vector<uint8_t> payload;
	uint8_t first_seq = 0; /* sequence id of the first wire packet */
	uint8_t last_seq = 0;  /* sequence id of the final wire packet */
	size_t wire_size = 0;  /* total bytes on the wire, headers included */
};

/*
 * Incremental framer. Feed it whatever arrives -- a partial packet, several
 * packets at once, a packet split across many calls -- and pull complete
 * logical messages back out.
 *
 * This exists because neither send() nor recv() respects message boundaries:
 * a single SSL_read may deliver half a packet or three of them.
 */
class MessageReader {
public:
	void append(const uint8_t *data, size_t len);
	void append(std::string_view s);

	/* Pull the next complete message. Returns false if more bytes are
	 * needed, leaving `out` untouched. */
	bool next(Message &out);

	/* Bytes held but not yet formed into a complete message. */
	size_t buffered() const
	{
		return buf_.size() - consumed_;
	}

	/* Discard all state. Use when a connection resets or when switching
	 * from the plaintext handshake phase into TLS. */
	void reset();

private:
	void compact();

	std::vector<uint8_t> buf_;
	size_t consumed_ = 0;
};

/* Server's initial handshake (Protocol::HandshakeV10). Sent in plaintext on
 * every connection, including those about to upgrade to TLS -- which is why
 * detecting TLS by "does the first message parse as MySQL" does not work,
 * and why CLIENT_SSL in the client's reply is the real signal. */
struct ServerHandshake {
	uint8_t protocol_version = 0;
	std::string server_version;
	uint32_t connection_id = 0;
	std::vector<uint8_t> scramble; /* auth-plugin-data, both parts joined */
	uint32_t capabilities = 0;
	uint8_t charset = 0;
	uint16_t status_flags = 0;
	std::string auth_plugin;
};

bool parseServerHandshake(const uint8_t *data, size_t len, ServerHandshake &out);

/* Client's reply. An SSLRequest is a HandshakeResponse41 truncated right
 * before the username, so the two are distinguished by length: if the
 * payload stops after the fixed 32-byte prefix, it is an SSLRequest and the
 * connection is about to go encrypted. */
struct ClientHandshake {
	uint32_t capabilities = 0;
	uint32_t max_packet_size = 0;
	uint8_t charset = 0;
	bool ssl_request = false; /* truncated form: TLS upgrade follows */
	std::string username;
	std::string database;
};

bool parseClientHandshake(const uint8_t *data, size_t len, ClientHandshake &out);

/* The capabilities actually in force on a connection are the intersection of
 * what both sides advertised. */
inline uint32_t negotiate(uint32_t server_caps, uint32_t client_caps)
{
	return server_caps & client_caps;
}

/*
 * Extract the statement text from a COM_QUERY payload.
 *
 * `caps` must be the negotiated capabilities. When CLIENT_QUERY_ATTRIBUTES
 * is in force (MySQL 8.0.26+), two length-encoded integers -- parameter_count
 * and parameter_set_count -- sit between the command byte and the statement,
 * and any declared parameters follow them. Knowing the flag makes this an
 * exact parse; without it, all one can do is guess from content, which is
 * what this project used to do.
 *
 * Returns false if the payload is not a COM_QUERY or is malformed. On
 * success `out` points into `data` and stays valid only as long as it does.
 */
bool extractQuery(const uint8_t *data, size_t len, uint32_t caps, std::string_view &out);

enum class ResponseKind {
	Ok,
	Err,
	Eof,
	LocalInfile,
	ResultSet, /* leading column count; column defs and rows follow */
	Unknown,
};

ResponseKind classifyResponse(const uint8_t *data, size_t len, uint32_t caps);

struct OkPacket {
	uint64_t affected_rows = 0;
	uint64_t last_insert_id = 0;
	uint16_t status_flags = 0;
	uint16_t warnings = 0;
};

/* Parse an OK (or, when CLIENT_DEPRECATE_EOF is set, an EOF-shaped OK).
 * The status flags are the reason this matters: SERVER_STATUS_IN_TRANS
 * decides whether caching is permitted. */
bool parseOk(const uint8_t *data, size_t len, uint32_t caps, OkPacket &out);

struct EofPacket {
	uint16_t warnings = 0;
	uint16_t status_flags = 0;
};

/*
 * Parse a genuine EOF packet: 0xFE, warnings, status flags. Five bytes.
 *
 * This is NOT a short OK packet, and parseOk() cannot stand in for it. An OK
 * puts two length-encoded integers where EOF puts its warning count, so the
 * status flags land at the same offset by coincidence -- and parseOk() then
 * fails on the trailing warnings field that an EOF does not have, discarding
 * a status it had already read correctly. That silently lost
 * SERVER_STATUS_IN_TRANS on every connection without CLIENT_DEPRECATE_EOF,
 * which would have made responses produced inside a transaction look
 * cacheable.
 */
bool parseEof(const uint8_t *data, size_t len, EofPacket &out);

struct ErrPacket {
	uint16_t error_code = 0;
	std::string sql_state;
	std::string message;
};

bool parseErr(const uint8_t *data, size_t len, uint32_t caps, ErrPacket &out);

/*
 * Rewrite the sequence ids of a serialized packet stream in place, so the
 * first wire packet carries `start_seq` and each subsequent one increments
 * (wrapping at 256).
 *
 * This is what makes a cached response replayable. MySQL resets the sequence
 * id at the start of each command, so a response captured mid-session cannot
 * simply be replayed onto a connection whose counter sits elsewhere -- the
 * client will reject it as out of order. Renumbering is a mechanical rewrite
 * of one byte per packet, but it has to walk the chain to find them.
 *
 * Returns false if the stream is not a well-formed packet sequence.
 */
bool renumber(std::vector<uint8_t> &stream, uint8_t start_seq);

/* Serialize a payload as one or more wire packets, applying the >=16 MiB
 * split rule. Mainly used by tests and by response synthesis. */
std::vector<uint8_t> encodeMessage(const uint8_t *payload, size_t len, uint8_t start_seq);

/* Length-encoded integer decoding. Advances `pos` past the value. Returns
 * false on truncation. Length-encoded integers appear throughout the
 * protocol and are the main source of off-by-one bugs when hand-rolled. */
bool readLenEnc(const uint8_t *data, size_t len, size_t &pos, uint64_t &out);

/* Length-encoded string. On success `out` points into `data`. */
bool readLenEncString(const uint8_t *data, size_t len, size_t &pos, std::string_view &out);

} // namespace mysql

#endif /* VALKEY_EBPF_MYSQL_PROTOCOL_H */
