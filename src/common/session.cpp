// SPDX-License-Identifier: GPL-2.0
#include "session.h"

namespace bncl {

void RequestTracker::begin(uint32_t c)
{
    caps = c;
    last_cmd = 0;
    last_seq = 0;
    reader.reset();
}

void RequestTracker::reset()
{
    last_cmd = 0;
    last_seq = 0;
    reader.reset();
}

bool RequestTracker::feed(const uint8_t *data, size_t len, std::string &out)
{
    if (data && len) {
        reader.append(data, len);
    }
    return next(out);
}

bool RequestTracker::next(std::string &out)
{
    bncl::mysql_proto::Message m;

    while (reader.next(m)) {
        if (m.payload.empty()) {
            continue;
        }
        last_cmd = m.payload[0];
        last_seq = m.last_seq;

        std::string_view q;

        /* Anything that is not a bncl::mysql_proto::COM_QUERY is consumed and skipped.
         * Skipping means "having parsed it", not "having ignored the
         * bytes" -- the reader has already advanced past the whole
         * packet, which is what keeps the stream aligned. */
        if (m.payload[0] != bncl::mysql_proto::COM_QUERY) {
            continue;
        }
        if (!bncl::mysql_proto::extractQuery(m.payload.data(), m.payload.size(), caps, q)) {
            continue;
        }
        out.assign(q.data(), q.size());
        return true;
    }
    return false;
}

void ResponseTracker::begin(uint32_t caps)
{
    state_ = State::Init;
    caps_ = caps;
    columns_left_ = 0;
    poisoned_ = false;
    in_transaction_ = false;
}

/* Pull the transaction flag out of the terminating packet. This is the whole
 * reason the tracker bothers walking to the end of a result set rather than
 * just counting bytes: bncl::mysql_proto::SERVER_STATUS_IN_TRANS decides whether the response
 * may be cached at all. */
void ResponseTracker::finish(const bncl::mysql_proto::Message &msg)
{
    const uint8_t *p = msg.payload.data();
    size_t n = msg.payload.size();
    uint16_t status = 0;
    bool got = false;

    /* Which terminator this is depends on what the two sides negotiated.
     * Without bncl::mysql_proto::CLIENT_DEPRECATE_EOF it is a real five-byte EOF, whose layout
     * differs from OK -- warnings come BEFORE the status flags, not after.
     * bncl::mysql_proto::parseOk() cannot read it: it happens to find the status at the right
     * offset and then fails on a trailing field EOF does not have, throwing
     * the answer away. */
    if (n >= 1 && p[0] == 0xFE && n < 9 && !(caps_ & bncl::mysql_proto::CLIENT_DEPRECATE_EOF)) {
        bncl::mysql_proto::EofPacket eof;

        got = bncl::mysql_proto::parseEof(p, n, eof);
        status = eof.status_flags;
    }
    else {
        bncl::mysql_proto::OkPacket ok;

        got = bncl::mysql_proto::parseOk(p, n, caps_, ok);
        status = ok.status_flags;
    }

    if (got) {
        in_transaction_ = (status & bncl::mysql_proto::SERVER_STATUS_IN_TRANS) != 0;
        if (status & bncl::mysql_proto::SERVER_MORE_RESULTS_EXISTS) {
            /* Multi-result-set responses need every set captured to
             * replay correctly. Out of scope; refuse to cache
             * rather than store a truncated answer. */
            poisoned_ = true;
        }
    }
    state_ = State::Done;
}

bool ResponseTracker::feed(const bncl::mysql_proto::Message &msg)
{
    const uint8_t *p = msg.payload.data();
    size_t n = msg.payload.size();

    if (state_ == State::Done) {
        return true;
    }
    if (n == 0) {
        return false;
    }

    switch (state_) {
    case State::Init: {
        bncl::mysql_proto::ResponseKind kind = bncl::mysql_proto::classifyResponse(p, n, caps_);

        switch (kind) {
        case bncl::mysql_proto::ResponseKind::Ok:
            finish(msg);
            return true;
        case bncl::mysql_proto::ResponseKind::Err:
            /* Errors are cheap to reproduce and may be
             * session-specific; never cache them. */
            poisoned_ = true;
            state_ = State::Done;
            return true;
        case bncl::mysql_proto::ResponseKind::LocalInfile:
            poisoned_ = true;
            state_ = State::Done;
            return true;
        case bncl::mysql_proto::ResponseKind::Eof:
            finish(msg);
            return true;
        case bncl::mysql_proto::ResponseKind::ResultSet: {
            size_t pos = 0;
            uint64_t cols = 0;

            if (!bncl::mysql_proto::readLenEnc(p, n, pos, cols) || cols == 0) {
                poisoned_ = true;
                state_ = State::Done;
                return true;
            }
            columns_left_ = cols;
            state_ = State::ColumnDefs;
            return false;
        }
        default:
            poisoned_ = true;
            state_ = State::Done;
            return true;
        }
    }

    case State::ColumnDefs:
        if (columns_left_ > 0) {
            columns_left_--;
        }
        if (columns_left_ == 0) {
            /* With bncl::mysql_proto::CLIENT_DEPRECATE_EOF there is no EOF packet
             * between the column definitions and the rows. */
            state_ =
                (caps_ & bncl::mysql_proto::CLIENT_DEPRECATE_EOF) ? State::Rows : State::ColumnEof;
        }
        return false;

    case State::ColumnEof:
        state_ = State::Rows;
        return false;

    case State::Rows: {
        uint8_t h = p[0];

        if (h == 0xFF) {
            poisoned_ = true;
            state_ = State::Done;
            return true;
        }
        /* Terminator: a short 0xFE packet, in either its EOF or its
         * DEPRECATE_EOF-era OK form. A longer 0xFE-led packet is a row
         * whose first column value simply starts with that byte. */
        if (h == 0xFE && n < 9) {
            finish(msg);
            return true;
        }
        return false; /* an ordinary row */
    }

    default:
        state_ = State::Done;
        return true;
    }
}

} // namespace bncl
