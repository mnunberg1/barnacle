// SPDX-License-Identifier: GPL-2.0
#include "session.h"

namespace cache {

using namespace mysql;

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
 * just counting bytes: SERVER_STATUS_IN_TRANS decides whether the response
 * may be cached at all. */
void ResponseTracker::finish(const Message &msg)
{
	OkPacket ok;

	if (parseOk(msg.payload.data(), msg.payload.size(), caps_, ok)) {
		in_transaction_ = (ok.status_flags & SERVER_STATUS_IN_TRANS) != 0;
		if (ok.status_flags & SERVER_MORE_RESULTS_EXISTS) {
			/* Multi-result-set responses need every set captured to
			 * replay correctly. Out of scope; refuse to cache
			 * rather than store a truncated answer. */
			poisoned_ = true;
		}
	}
	state_ = State::Done;
}

bool ResponseTracker::feed(const Message &msg)
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
		ResponseKind kind = classifyResponse(p, n, caps_);

		switch (kind) {
		case ResponseKind::Ok:
			finish(msg);
			return true;
		case ResponseKind::Err:
			/* Errors are cheap to reproduce and may be
			 * session-specific; never cache them. */
			poisoned_ = true;
			state_ = State::Done;
			return true;
		case ResponseKind::LocalInfile:
			poisoned_ = true;
			state_ = State::Done;
			return true;
		case ResponseKind::Eof:
			finish(msg);
			return true;
		case ResponseKind::ResultSet: {
			size_t pos = 0;
			uint64_t cols = 0;

			if (!readLenEnc(p, n, pos, cols) || cols == 0) {
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
			/* With CLIENT_DEPRECATE_EOF there is no EOF packet
			 * between the column definitions and the rows. */
			state_ = (caps_ & CLIENT_DEPRECATE_EOF) ? State::Rows
								: State::ColumnEof;
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

} // namespace cache
