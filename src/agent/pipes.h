// SPDX-License-Identifier: GPL-2.0
/*
 * pipes.h - the agent_pipe pool.
 *
 * A pipe is a loopback TCP connection the daemon makes to itself. The daemon
 * holds both ends: it writes the mini-protocol into one, and KCLIENT's sk_msg
 * program redirects those bytes into the paired client socket's receive
 * queue instead of letting them travel to the other end.
 *
 * Loopback TCP rather than socketpair() because sockmap redirect wants real
 * TCP sockets, and because both ends have addresses, which gives each a
 * sock_key that the BPF side can name.
 *
 * Pipes are pooled and reused. Creating a connection per query would put a
 * TCP handshake on the fast path, which is the opposite of the point.
 */
#ifndef VALKEY_EBPF_DAEMON_PIPES_H
#define VALKEY_EBPF_DAEMON_PIPES_H

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

extern "C" {
#include "kclient.h"
}

/* Namespace is `qcd`, not `daemon`: <unistd.h> declares daemon(int, int),
 * and a namespace of that name collides with it. */
namespace qcd {

struct AgentPipe {
	uint32_t key = 0;  /* assigned from key_serial */
	int local_fd = -1; /* the end the daemon writes into */
	int peer_fd = -1;  /* the far end; held open so the connection lives */
	sock_key skey {};  /* local_fd's key, as the BPF side computes it */
	bool in_use = false;
};

class PipePool {
public:
	/* Create `count` pipes and register each one's local end in the
	 * sockmap. Returns false if the pool could not be built. */
	bool init(int sock_map_fd, int pipe_pairs_fd, size_t count);

	/* Take a pipe off the free list and pair it with a client socket, so
	 * KCLIENT redirects this pipe's writes into that client. Returns
	 * nullptr when the pool is exhausted -- callers must fall back to
	 * passing the query through rather than blocking. */
	AgentPipe *acquire(const sock_key &client);

	/* Undo the pairing and return the pipe to the free list. Called once
	 * the client has consumed the response; leaving the pairing in place
	 * would redirect a later, unrelated write. */
	void release(AgentPipe *p);

	AgentPipe *byKey(uint32_t key);

	size_t freeCount();
	size_t size() const
	{
		return pipes_.size();
	}

	void shutdown();

private:
	bool makePipe(AgentPipe &p);

	std::mutex lock_;
	std::deque<AgentPipe> pipes_;
	std::vector<uint32_t> free_list_;
	std::map<uint32_t, AgentPipe *> by_key_;
	uint32_t key_serial_ = 1;
	int listen_fd_ = -1;
	int sock_map_fd_ = -1;
	int pipe_pairs_fd_ = -1;
};

/* Compute a socket's sock_key the way the BPF side does.
 *
 * The port encoding is the trap: BPF stores ports as htonl(port_number),
 * whereas sockaddr_in::sin_port is a 16-bit network value that zero-extends
 * to something different. Getting this wrong produces keys that never match
 * and a redirect that silently does nothing.
 */
bool sockKeyOf(int fd, sock_key &out);

} // namespace qcd

#endif /* VALKEY_EBPF_DAEMON_PIPES_H */
