// SPDX-License-Identifier: GPL-2.0
#include "common/mysql/resultset.h"

#include <cstring>

namespace bncl::mysql_proto {
namespace {

/* --- writing ------------------------------------------------------------- */

void putU16(std::vector<uint8_t> &v, uint16_t x)
{
    v.push_back((uint8_t)(x & 0xFF));
    v.push_back((uint8_t)(x >> 8));
}

void putU32(std::vector<uint8_t> &v, uint32_t x)
{
    for (int i = 0; i < 4; i++) {
        v.push_back((uint8_t)((x >> (8 * i)) & 0xFF));
    }
}

/* Length-encoded integer. The width is chosen by magnitude, and a value below
 * 0xFB must use the one-byte form -- the wider forms are legal encodings of
 * the same number but no server emits them, so writing one would make a
 * re-encoded response differ from the original byte for byte. */
void putLenEnc(std::vector<uint8_t> &v, uint64_t x)
{
    if (x < 0xFB) {
        v.push_back((uint8_t)x);
    }
    else if (x <= 0xFFFF) {
        v.push_back(0xFC);
        putU16(v, (uint16_t)x);
    }
    else if (x <= 0xFFFFFF) {
        v.push_back(0xFD);
        for (int i = 0; i < 3; i++) {
            v.push_back((uint8_t)((x >> (8 * i)) & 0xFF));
        }
    }
    else {
        v.push_back(0xFE);
        for (int i = 0; i < 8; i++) {
            v.push_back((uint8_t)((x >> (8 * i)) & 0xFF));
        }
    }
}

void putLenEncStr(std::vector<uint8_t> &v, const std::string &s)
{
    putLenEnc(v, s.size());
    v.insert(v.end(), s.begin(), s.end());
}

/* Append one payload as a wire packet and advance the sequence id. */
void emit(std::vector<uint8_t> &out, const std::vector<uint8_t> &payload, uint8_t &seq)
{
    std::vector<uint8_t> pkt = encodeMessage(payload.data(), payload.size(), seq);

    out.insert(out.end(), pkt.begin(), pkt.end());
    seq++;
}

std::vector<uint8_t> columnPayload(const Column &c)
{
    std::vector<uint8_t> p;

    putLenEncStr(p, c.catalog);
    putLenEncStr(p, c.schema);
    putLenEncStr(p, c.table);
    putLenEncStr(p, c.org_table);
    putLenEncStr(p, c.name);
    putLenEncStr(p, c.org_name);
    /* Length of the fixed-width tail that follows. Always 0x0c. */
    putLenEnc(p, 0x0c);
    putU16(p, c.charset);
    putU32(p, c.length);
    p.push_back(c.type);
    putU16(p, c.flags);
    p.push_back(c.decimals);
    putU16(p, 0); /* filler */
    return p;
}

std::vector<uint8_t> rowPayload(const Row &r)
{
    std::vector<uint8_t> p;

    for (const Value &v : r) {
        if (!v) {
            p.push_back(0xFB); /* SQL NULL */
        }
        else {
            putLenEncStr(p, *v);
        }
    }
    return p;
}

/* The terminating packet, whose shape depends on what was negotiated: a real
 * five-byte EOF, or an OK packet wearing an 0xFE header. */
std::vector<uint8_t> terminator(const ResultSet &rs, uint32_t caps)
{
    std::vector<uint8_t> p;

    p.push_back(0xFE);
    if (caps & CLIENT_DEPRECATE_EOF) {
        putLenEnc(p, 0); /* affected_rows */
        putLenEnc(p, 0); /* last_insert_id */
        putU16(p, rs.status);
        putU16(p, rs.warnings);
    }
    else {
        putU16(p, rs.warnings);
        putU16(p, rs.status);
    }
    return p;
}

/* --- reading ------------------------------------------------------------- */

bool getLenEncStr(const uint8_t *d, size_t len, size_t &pos, std::string &out)
{
    std::string_view sv;

    if (!readLenEncString(d, len, pos, sv)) {
        return false;
    }
    out.assign(sv.data(), sv.size());
    return true;
}

bool parseColumn(const Message &m, Column &c)
{
    const uint8_t *d = m.payload.data();
    size_t len = m.payload.size();
    size_t pos = 0;
    uint64_t fixed = 0;

    if (!getLenEncStr(d, len, pos, c.catalog) || !getLenEncStr(d, len, pos, c.schema) ||
        !getLenEncStr(d, len, pos, c.table) || !getLenEncStr(d, len, pos, c.org_table) ||
        !getLenEncStr(d, len, pos, c.name) || !getLenEncStr(d, len, pos, c.org_name)) {
        return false;
    }
    if (!readLenEnc(d, len, pos, fixed) || pos + 10 > len) {
        return false;
    }
    c.charset = (uint16_t)(d[pos] | (d[pos + 1] << 8));
    pos += 2;
    c.length = (uint32_t)d[pos] | ((uint32_t)d[pos + 1] << 8) | ((uint32_t)d[pos + 2] << 16) |
               ((uint32_t)d[pos + 3] << 24);
    pos += 4;
    c.type = d[pos++];
    c.flags = (uint16_t)(d[pos] | (d[pos + 1] << 8));
    pos += 2;
    c.decimals = d[pos];
    return true;
}

bool parseRow(const Message &m, size_t ncols, Row &r)
{
    const uint8_t *d = m.payload.data();
    size_t len = m.payload.size();
    size_t pos = 0;

    r.clear();
    for (size_t i = 0; i < ncols; i++) {
        if (pos >= len) {
            return false;
        }
        if (d[pos] == 0xFB) {
            pos++;
            r.push_back(std::nullopt);
            continue;
        }

        std::string s;

        if (!getLenEncStr(d, len, pos, s)) {
            return false;
        }
        r.push_back(std::move(s));
    }
    return true;
}

} // namespace

std::vector<uint8_t> encodeResultSet(const ResultSet &rs, uint32_t caps, uint8_t seq)
{
    std::vector<uint8_t> out;
    std::vector<uint8_t> p;

    /* Column count. */
    putLenEnc(p, rs.cols.size());
    emit(out, p, seq);

    for (const Column &c : rs.cols) {
        emit(out, columnPayload(c), seq);
    }

    /* Without DEPRECATE_EOF an EOF packet separates the definitions from
     * the rows. Its status is the same one the response ended with; no
     * client is known to read it, but emitting a different value would
     * make a re-encode differ from the capture. */
    if (!(caps & CLIENT_DEPRECATE_EOF)) {
        std::vector<uint8_t> eof;

        eof.push_back(0xFE);
        putU16(eof, rs.warnings);
        putU16(eof, rs.status);
        emit(out, eof, seq);
    }

    for (const Row &r : rs.rows) {
        emit(out, rowPayload(r), seq);
    }

    emit(out, terminator(rs, caps), seq);
    return out;
}

bool parseResultSet(const uint8_t *data, size_t len, uint32_t caps, ResultSet &out)
{
    MessageReader rd;
    Message m;
    uint64_t ncols = 0;

    out.cols.clear();
    out.rows.clear();
    out.status = 0;
    out.warnings = 0;

    rd.append(data, len);

    /* Header: a length-encoded column count. Anything else -- OK, ERR,
     * LOCAL INFILE -- is not a result set and is not ours to cache. */
    if (!rd.next(m) || m.payload.empty()) {
        return false;
    }
    if (classifyResponse(m.payload.data(), m.payload.size(), caps) != ResponseKind::ResultSet) {
        return false;
    }

    size_t pos = 0;

    if (!readLenEnc(m.payload.data(), m.payload.size(), pos, ncols) || ncols == 0) {
        return false;
    }

    for (uint64_t i = 0; i < ncols; i++) {
        Column c;

        if (!rd.next(m) || !parseColumn(m, c)) {
            return false;
        }
        out.cols.push_back(std::move(c));
    }

    if (!(caps & CLIENT_DEPRECATE_EOF)) {
        /* The separator. Consumed, not interpreted: the status that
         * matters is on the terminator. */
        if (!rd.next(m)) {
            return false;
        }
    }

    for (;;) {
        if (!rd.next(m) || m.payload.empty()) {
            return false; /* ran out before the terminator */
        }

        const uint8_t *d = m.payload.data();
        size_t n = m.payload.size();

        if (d[0] == 0xFF) {
            return false; /* error mid-stream; do not cache */
        }

        /* 0xFE terminates only when short. A longer 0xFE-led packet is
         * an ordinary row whose first value happens to start with that
         * byte. */
        if (d[0] == 0xFE && n < 9) {
            size_t p = 1;

            if (caps & CLIENT_DEPRECATE_EOF) {
                uint64_t affected = 0, insert_id = 0;

                readLenEnc(d, n, p, affected);
                readLenEnc(d, n, p, insert_id);
                if (p + 4 <= n) {
                    out.status = (uint16_t)(d[p] | (d[p + 1] << 8));
                    out.warnings = (uint16_t)(d[p + 2] | (d[p + 3] << 8));
                }
            }
            else if (n >= 5) {
                out.warnings = (uint16_t)(d[1] | (d[2] << 8));
                out.status = (uint16_t)(d[3] | (d[4] << 8));
            }
            return true;
        }

        Row r;

        if (!parseRow(m, out.cols.size(), r)) {
            return false;
        }
        out.rows.push_back(std::move(r));
    }
}

} // namespace bncl::mysql_proto
