// SPDX-License-Identifier: GPL-2.0
#pragma once
/*
 * shared.h - the agent's side of the daemon's shared state.
 *
 * Deliberately a separate translation unit from the Frida hooks. frida-gum.h
 * bundles its own disassembler, which declares `bpf_insn` as an enum, while
 * libbpf's bpf.h declares it as a struct -- including both in one file is a
 * hard compile error. Keeping the map access here means neither header ever
 * meets the other.
 *
 * The bpf(2) calls are plain syscalls (see bpfsys.h), not libbpf: the agent
 * opens pins the daemon already made and mmaps the arena. It never creates a
 * map or loads a program, so everything libbpf would add is weight that has
 * to exist in whatever container we are injected into.
 *
 * --- nothing here blocks --------------------------------------------------
 *
 * Every function below is called from inside SSL_read or SSL_write, on the
 * application's own thread. The application may have set its socket
 * non-blocking and is entitled to expect those calls to behave. So nothing
 * here waits for the daemon: a request is posted and the caller returns. The
 * answer arrives on the client's own socket, which the redirect delivers to,
 * and the application collects it whenever its own event loop comes round --
 * which is the whole reason architecture.txt routes the conversation through
 * the hijacked connection rather than a side channel.
 *
 * Reading that answer is a different matter, and is not here: agent.cpp waits
 * briefly for the verdict, bounded by a deadline, because that is the one
 * place a wait is unavoidable.
 *
 * The one exception below is the freelist lock, which spins. Bounded to
 * roughly a millisecond and abandoned rather than waited out, because the
 * cost of failing to take a pipe is one query going to the server, and the
 * cost of waiting forever is an application hung inside SSL_write for a cache.
 */

#include <cstdint>
#include <string>
#include <vector>

namespace bnclagent
{

/*
 * The capabilities a cached response is stored under.
 *
 * Mirrors BNCL_CANONICAL_CAPS in common/defs.h. Repeated rather than included
 * because defs.h reaches <linux/bpf.h>, which cannot meet frida-gum.h.
 */
constexpr uint32_t CANONICAL_CAPS = 0x01002200u;

/*
 * The daemon's four-byte verdict, and the statuses it can carry.
 *
 * Mirrors struct agent_reply and enum agent_status in common/defs.h, for the
 * same reason as above: agent.cpp needs frida-gum.h and defs.h cannot be in
 * the same translation unit as it. A static_assert in shared.cpp checks the
 * two definitions have not drifted.
 */
struct Reply {
    uint8_t status;
    uint8_t pad[3];
    uint32_t stmt_id;
};

constexpr uint8_t REPLY_OK = 0x01;
constexpr uint8_t REPLY_WRITE_THROUGH = 0x00;
constexpr uint8_t REPLY_CACHE_ERROR = 0xff;

/*
 * Map the arena at the address the daemon chose and open the pins. False if
 * the daemon is not running.
 *
 * Safe to call again. It closes what it already had first, which is what a
 * re-attach after the daemon was restarted needs: the descriptors from the
 * previous daemon still refer to perfectly valid maps that nobody is reading
 * any more, and using them would be worse than having none.
 */
bool openShared();

/*
 * Is the daemon still there?
 *
 * Answered by whether its pins still exist, because holding a descriptor
 * proves nothing: a BPF map outlives every pin and every process that made
 * it, for as long as one descriptor remains open -- and this agent is holding
 * those descriptors. So a dead daemon leaves the agent with a complete,
 * readable, permanently unanswered set of maps.
 *
 * The daemon removes its pins on the way out, which makes their absence the
 * signal. Cheap enough to ask on every poll: one stat of a path that is
 * almost certainly in the dentry cache.
 */
bool daemonAlive();

/*
 * The runtime switches the daemon publishes, read together.
 *
 * `client_on` is cleared by `barnacle detach-client`, `generation` is bumped
 * by `barnacle reload-config`, and `local_on` says whether the arena copy may
 * be trusted or every lookup has to go to Valkey. Polled rather than pushed:
 * there is no thread here to receive a notification on, and the agent is only
 * ever running inside somebody else's SSL_write.
 *
 * One struct rather than three out-parameters because they are read together,
 * in one place, and adding a fourth should not change a signature.
 */
struct Switches {
    uint32_t client_on;
    uint32_t generation;
    uint32_t local_on;
};

/*
 * False when the daemon is gone or the pin cannot be read, in which case the
 * caller keeps whatever it last saw.
 */
bool cfgRead(Switches &out);

/*
 * The cached response for a statement, if present and unexpired.
 *
 * The bytes come back in the canonical encoding, NOT ready for the wire: the
 * caller re-encodes them for its own connection's capabilities and sequence
 * numbering.
 */
bool lookupPayload(const std::string &sql, std::vector<uint8_t> &out, uint32_t &id);

/*
 * Take a dpipe and splice this connection to it.
 *
 * Pops dpipe_freelist, points the pipe at the statement's record, and
 * registers `sock` so the daemon's reply is redirected into it. From here the
 * socket is a control channel between the client and the daemon rather than a
 * path to the server.
 *
 * False when the pool is exhausted, which is not an error: the query goes to
 * the server as it normally would.
 */
bool acquire(const std::string &sql, int sock, uint32_t &key);

/* Ask the daemon to resolve the spliced statement. Posts the request and
 * returns; the reply arrives on `sock` later. */
bool askLookup(int sock);

/* Hand back a response read from the server so the daemon can cache it. The
 * bytes must already be canonicalised. Posts and returns. */
bool askStore(int sock, const std::vector<uint8_t> &canonical);

/* Undo the splice and put the dpipe back on the freelist. Leaving it spliced
 * would redirect the connection's next write into the daemon. */
void release(int sock, uint32_t key);

} // namespace bnclagent
