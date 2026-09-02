// SPDX-License-Identifier: GPL-2.0
#pragma once
/*
 * resultset.h - a response as data, rather than as bytes.
 *
 * Caching raw wire bytes and replaying them only works between connections
 * that agreed on the same things. A response captured where
 * CLIENT_DEPRECATE_EOF was negotiated has one fewer packet than the same rows
 * on a connection without it, so replaying the bytes puts the client's parser
 * a packet out of step -- and sequence ids are per-command, so a capture taken
 * mid-cycle replays with the wrong numbering.
 *
 * Holding the result set instead makes the cached thing independent of the
 * connection it came from. The daemon stores columns and rows; the wire
 * packets are generated fresh for whoever is asking, with their capabilities
 * and their sequence numbering. That is what lets one cached answer serve a
 * Python client and a mysql CLI that negotiated differently.
 *
 * Round-tripping is exact for a response this can represent: parse then
 * encode with the same capabilities reproduces the original bytes, which is
 * how the tests check it -- against a response captured from a real server
 * rather than one this code made up.
 */

#include "common/mysql/protocol.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace mysql {

/* Protocol::ColumnDefinition41. Every field is kept, including the ones this
 * project never reads: they go back on the wire verbatim, and a client is
 * entitled to care about any of them. */
struct Column {
    std::string catalog; /* always "def" in practice */
    std::string schema;
    std::string table;
    std::string org_table;
    std::string name;
    std::string org_name;
    uint16_t charset = 0;
    uint32_t length = 0;
    uint8_t type = 0;
    uint16_t flags = 0;
    uint8_t decimals = 0;
};

/* One field. Empty optional is SQL NULL, which is distinct from the empty
 * string -- on the wire the first is 0xFB and the second is a zero-length
 * length-encoded string. */
using Value = std::optional<std::string>;
using Row = std::vector<Value>;

struct ResultSet {
    std::vector<Column> cols;
    std::vector<Row> rows;

    /* From the terminating packet. status carries SERVER_STATUS_IN_TRANS,
     * which decides whether the response was safe to cache at all. */
    uint16_t status = 0;
    uint16_t warnings = 0;
};

/*
 * Parse a complete COM_QUERY response.
 *
 * `caps` must be what the capturing connection negotiated -- it decides
 * whether an EOF packet separates the column definitions from the rows.
 * Returns false for anything that is not a plain result set: an OK, an error,
 * a LOCAL INFILE request, or a truncated capture.
 */
bool parseResultSet(const uint8_t *data, size_t len, uint32_t caps, ResultSet &out);

/*
 * Generate the wire packets for a result set.
 *
 * `caps` is the TARGET connection's, not the one it was captured on, and
 * `seq` is where that connection's numbering currently stands -- for a
 * response to a COM_QUERY that is 1, since a command resets the counter.
 */
std::vector<uint8_t> encodeResultSet(const ResultSet &rs, uint32_t caps, uint8_t seq);

} // namespace mysql
