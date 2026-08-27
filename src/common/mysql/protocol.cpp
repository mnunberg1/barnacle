// SPDX-License-Identifier: GPL-2.0
#include "protocol.h"

#include <cstring>

namespace mysql {
namespace {

inline uint32_t readU24(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

inline uint16_t readU16(const uint8_t *p)
{
	return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

inline uint32_t readU32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

/* Read a NUL-terminated string. Advances pos past the terminator. */
bool readNulString(const uint8_t *data, size_t len, size_t &pos, std::string &out)
{
	size_t start = pos;

	while (pos < len && data[pos] != 0) {
		pos++;
	}
	if (pos >= len) {
		return false; /* unterminated */
	}
	out.assign((const char *)data + start, pos - start);
	pos++; /* consume the NUL */
	return true;
}

} // namespace

bool readLenEnc(const uint8_t *data, size_t len, size_t &pos, uint64_t &out)
{
	if (pos >= len) {
		return false;
	}
	uint8_t first = data[pos];

	/* 0xFB is NULL and 0xFF is an error packet marker; neither is a
	 * length. Treating them as one is a classic source of misparses. */
	if (first < 0xFB) {
		out = first;
		pos += 1;
		return true;
	}
	if (first == 0xFC) {
		if (pos + 3 > len) {
			return false;
		}
		out = readU16(data + pos + 1);
		pos += 3;
		return true;
	}
	if (first == 0xFD) {
		if (pos + 4 > len) {
			return false;
		}
		out = readU24(data + pos + 1);
		pos += 4;
		return true;
	}
	if (first == 0xFE) {
		if (pos + 9 > len) {
			return false;
		}
		uint64_t v = 0;

		for (int i = 7; i >= 0; i--) {
			v = (v << 8) | data[pos + 1 + i];
		}
		out = v;
		pos += 9;
		return true;
	}
	return false;
}

bool readLenEncString(const uint8_t *data, size_t len, size_t &pos, std::string_view &out)
{
	uint64_t n;

	if (!readLenEnc(data, len, pos, n)) {
		return false;
	}
	if (n > len - pos) {
		return false;
	}
	out = std::string_view((const char *)data + pos, (size_t)n);
	pos += (size_t)n;
	return true;
}

/* --- MessageReader -------------------------------------------------- */

void MessageReader::append(const uint8_t *data, size_t len)
{
	if (len == 0) {
		return;
	}
	compact();
	buf_.insert(buf_.end(), data, data + len);
}

void MessageReader::append(std::string_view s)
{
	append((const uint8_t *)s.data(), s.size());
}

void MessageReader::reset()
{
	buf_.clear();
	consumed_ = 0;
}

/* Drop already-consumed bytes once they dominate the buffer. Without this a
 * long-lived connection's buffer grows without bound. */
void MessageReader::compact()
{
	if (consumed_ == 0) {
		return;
	}
	if (consumed_ == buf_.size()) {
		buf_.clear();
		consumed_ = 0;
		return;
	}
	if (consumed_ > (buf_.size() / 2)) {
		buf_.erase(buf_.begin(), buf_.begin() + (long)consumed_);
		consumed_ = 0;
	}
}

bool MessageReader::next(Message &out)
{
	size_t pos = consumed_;
	const size_t end = buf_.size();
	std::vector<uint8_t> payload;
	bool first = true;
	uint8_t first_seq = 0, last_seq = 0;

	/* Walk the continuation chain without consuming anything, so an
	 * incomplete message leaves the reader's state untouched and the
	 * caller can simply try again after more bytes arrive. */
	for (;;) {
		if (end - pos < kHeaderLen) {
			return false;
		}
		const uint8_t *hdr = buf_.data() + pos;
		uint32_t plen = readU24(hdr);
		uint8_t seq = hdr[3];

		if (end - pos - kHeaderLen < plen) {
			return false; /* body not fully arrived */
		}
		const uint8_t *body = hdr + kHeaderLen;

		if (first) {
			first_seq = seq;
			first = false;
		}
		last_seq = seq;
		payload.insert(payload.end(), body, body + plen);
		pos += kHeaderLen + plen;

		/* A full-size packet means the message continues in the next
		 * one. Anything shorter terminates it -- including a
		 * zero-length packet, which is exactly how a message whose
		 * length is a multiple of kMaxPayload is ended. */
		if (plen != kMaxPayload) {
			break;
		}
	}

	out.payload = std::move(payload);
	out.first_seq = first_seq;
	out.last_seq = last_seq;
	out.wire_size = pos - consumed_;
	consumed_ = pos;
	return true;
}

/* --- Handshake ------------------------------------------------------ */

bool parseServerHandshake(const uint8_t *data, size_t len, ServerHandshake &out)
{
	size_t pos = 0;

	if (len < 1) {
		return false;
	}
	out.protocol_version = data[pos++];
	if (out.protocol_version != 10) {
		return false; /* only HandshakeV10 is supported */
	}
	if (!readNulString(data, len, pos, out.server_version)) {
		return false;
	}
	if (pos + 4 > len) {
		return false;
	}
	out.connection_id = readU32(data + pos);
	pos += 4;

	/* auth-plugin-data-part-1 is always 8 bytes, followed by a filler. */
	if (pos + 9 > len) {
		return false;
	}
	out.scramble.assign(data + pos, data + pos + 8);
	pos += 8;
	pos += 1; /* filler */

	if (pos + 2 > len) {
		return false;
	}
	uint32_t caps_lo = readU16(data + pos);
	pos += 2;

	/* Everything past this point is optional in the protocol; a minimal
	 * server may stop here. */
	if (pos >= len) {
		out.capabilities = caps_lo;
		return true;
	}
	if (pos + 1 > len) {
		return false;
	}
	out.charset = data[pos++];
	if (pos + 2 > len) {
		return false;
	}
	out.status_flags = readU16(data + pos);
	pos += 2;
	if (pos + 2 > len) {
		return false;
	}
	uint32_t caps_hi = readU16(data + pos);
	pos += 2;
	out.capabilities = caps_lo | (caps_hi << 16);

	if (pos + 1 > len) {
		return false;
	}
	uint8_t auth_data_len = data[pos++];

	pos += 10; /* reserved */
	if (pos > len) {
		return false;
	}

	if (out.capabilities & CLIENT_SECURE_CONNECTION) {
		/* Part 2 length is max(13, total - 8); the trailing byte is a
		 * NUL that is not part of the scramble. */
		size_t part2 = auth_data_len > 8 ? (size_t)(auth_data_len - 8) : 13;

		if (part2 < 13) {
			part2 = 13;
		}
		if (pos + part2 > len) {
			return false;
		}
		size_t copy = part2 > 0 ? part2 - 1 : 0;

		out.scramble.insert(out.scramble.end(), data + pos, data + pos + copy);
		pos += part2;
	}

	if (out.capabilities & CLIENT_PLUGIN_AUTH) {
		std::string plugin;

		/* Some servers omit the trailing NUL on the final field. */
		if (readNulString(data, len, pos, plugin)) {
			out.auth_plugin = plugin;
		} else if (pos < len) {
			out.auth_plugin.assign((const char *)data + pos, len - pos);
		}
	}
	return true;
}

bool parseClientHandshake(const uint8_t *data, size_t len, ClientHandshake &out)
{
	size_t pos = 0;

	/* HandshakeResponse41 fixed prefix: 4-byte caps, 4-byte max packet
	 * size, 1-byte charset, 23 bytes reserved = 32 bytes. */
	if (len < 32) {
		return false;
	}
	out.capabilities = readU32(data + pos);
	pos += 4;
	out.max_packet_size = readU32(data + pos);
	pos += 4;
	out.charset = data[pos];
	pos += 1;
	pos += 23; /* reserved */

	/* An SSLRequest is exactly this prefix and nothing more -- it is a
	 * HandshakeResponse41 truncated before the username. That is the
	 * definitive signal that the connection is about to become TLS, and
	 * it is far more reliable than trying to infer encryption from
	 * whether subsequent bytes parse as MySQL. */
	if (pos >= len) {
		out.ssl_request = true;
		return true;
	}

	out.ssl_request = false;
	std::string user;

	if (!readNulString(data, len, pos, user)) {
		return true; /* prefix was valid; the rest may be truncated */
	}
	out.username = user;

	/* Auth response: length-encoded when CLIENT_PLUGIN_AUTH_LENENC is in
	 * play, otherwise a 1-byte length. We only need to step over it. */
	if (out.capabilities & CLIENT_SECURE_CONNECTION) {
		if (pos >= len) {
			return true;
		}
		uint8_t n = data[pos++];

		pos += n;
	} else {
		std::string ignored;

		if (!readNulString(data, len, pos, ignored)) {
			return true;
		}
	}

	if (out.capabilities & CLIENT_CONNECT_ATTRS) {
		/* database, if present, precedes attrs; handled below. */
	}
	if (pos < len) {
		std::string db;

		if (readNulString(data, len, pos, db)) {
			out.database = db;
		}
	}
	return true;
}

/* --- Commands ------------------------------------------------------- */

bool extractQuery(const uint8_t *data, size_t len, uint32_t caps, std::string_view &out)
{
	size_t pos = 0;

	if (len < 1 || data[0] != COM_QUERY) {
		return false;
	}
	pos = 1;

	/* This is the payoff for parsing the handshake. When
	 * CLIENT_QUERY_ATTRIBUTES is negotiated, parameter_count and
	 * parameter_set_count sit here as length-encoded integers, and any
	 * declared parameters follow. Knowing the flag makes the offset
	 * exact; without it one can only guess from content. */
	if (caps & CLIENT_QUERY_ATTRIBUTES) {
		uint64_t param_count = 0, param_set_count = 0;

		if (!readLenEnc(data, len, pos, param_count)) {
			return false;
		}
		if (!readLenEnc(data, len, pos, param_set_count)) {
			return false;
		}
		if (param_count > 0) {
			/* NULL bitmap, then a new-params-bound flag, then per
			 * parameter a 2-byte type and a length-encoded name;
			 * values follow. Statements with bound parameters are
			 * out of scope for caching, so bail rather than
			 * risk a misparse. */
			return false;
		}
	}

	if (pos > len) {
		return false;
	}
	out = std::string_view((const char *)data + pos, len - pos);
	return true;
}

/* --- Responses ------------------------------------------------------ */

ResponseKind classifyResponse(const uint8_t *data, size_t len, uint32_t caps)
{
	if (len < 1) {
		return ResponseKind::Unknown;
	}
	uint8_t h = data[0];

	if (h == 0xFF) {
		return ResponseKind::Err;
	}
	if (h == 0xFB) {
		return ResponseKind::LocalInfile;
	}
	if (h == 0x00) {
		/* An OK packet's header is 0x00. A result set beginning with a
		 * column count of zero is not legal, so this is unambiguous. */
		return ResponseKind::Ok;
	}
	if (h == 0xFE) {
		/* 0xFE is overloaded: a short packet is an EOF marker, while a
		 * longer one is either an OK packet in EOF clothing (when
		 * CLIENT_DEPRECATE_EOF is set) or a length-encoded column
		 * count whose first byte happens to be 0xFE. The length test
		 * is how the protocol itself disambiguates. */
		if (len < 9) {
			return (caps & CLIENT_DEPRECATE_EOF) ? ResponseKind::Ok
							     : ResponseKind::Eof;
		}
		return ResponseKind::ResultSet;
	}
	return ResponseKind::ResultSet;
}

bool parseOk(const uint8_t *data, size_t len, uint32_t caps, OkPacket &out)
{
	size_t pos = 0;

	if (len < 1) {
		return false;
	}
	if (data[0] != 0x00 && data[0] != 0xFE) {
		return false;
	}
	pos = 1;
	if (!readLenEnc(data, len, pos, out.affected_rows)) {
		return false;
	}
	if (!readLenEnc(data, len, pos, out.last_insert_id)) {
		return false;
	}
	if (caps & (CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS)) {
		if (pos + 2 > len) {
			return false;
		}
		out.status_flags = readU16(data + pos);
		pos += 2;
	}
	if (caps & CLIENT_PROTOCOL_41) {
		if (pos + 2 > len) {
			return false;
		}
		out.warnings = readU16(data + pos);
		pos += 2;
	}
	return true;
}

bool parseEof(const uint8_t *data, size_t len, EofPacket &out)
{
	/* Exactly five bytes, always: header, warnings, status. There is no
	 * capability-dependent tail the way an OK packet has. */
	if (len < 5 || data[0] != 0xFE) {
		return false;
	}
	out.warnings = readU16(data + 1);
	out.status_flags = readU16(data + 3);
	return true;
}

bool parseErr(const uint8_t *data, size_t len, uint32_t caps, ErrPacket &out)
{
	size_t pos = 0;

	if (len < 3 || data[0] != 0xFF) {
		return false;
	}
	pos = 1;
	out.error_code = readU16(data + pos);
	pos += 2;

	if (caps & CLIENT_PROTOCOL_41) {
		/* '#' marker followed by a 5-character SQL state. */
		if (pos < len && data[pos] == '#') {
			pos += 1;
			if (pos + 5 > len) {
				return false;
			}
			out.sql_state.assign((const char *)data + pos, 5);
			pos += 5;
		}
	}
	if (pos <= len) {
		out.message.assign((const char *)data + pos, len - pos);
	}
	return true;
}

/* --- Sequence renumbering and encoding ------------------------------ */

bool renumber(std::vector<uint8_t> &stream, uint8_t start_seq)
{
	size_t pos = 0;
	uint8_t seq = start_seq;

	while (pos < stream.size()) {
		if (stream.size() - pos < kHeaderLen) {
			return false; /* trailing garbage */
		}
		uint32_t plen = readU24(stream.data() + pos);

		if (stream.size() - pos - kHeaderLen < plen) {
			return false; /* truncated body */
		}
		stream[pos + 3] = seq++;
		pos += kHeaderLen + plen;
	}
	return pos == stream.size();
}

std::vector<uint8_t> encodeMessage(const uint8_t *payload, size_t len, uint8_t start_seq)
{
	std::vector<uint8_t> out;
	size_t off = 0;
	uint8_t seq = start_seq;

	for (;;) {
		size_t chunk = len - off;

		if (chunk > kMaxPayload) {
			chunk = kMaxPayload;
		}
		out.push_back((uint8_t)(chunk & 0xFF));
		out.push_back((uint8_t)((chunk >> 8) & 0xFF));
		out.push_back((uint8_t)((chunk >> 16) & 0xFF));
		out.push_back(seq++);
		out.insert(out.end(), payload + off, payload + off + chunk);
		off += chunk;

		/* Stop once a short packet has been emitted. A message that is
		 * an exact multiple of kMaxPayload needs a trailing
		 * zero-length packet to terminate it, which this loop
		 * produces naturally. */
		if (chunk != kMaxPayload) {
			break;
		}
	}
	return out;
}

} // namespace mysql
