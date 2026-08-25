// SPDX-License-Identifier: GPL-2.0
/*
 * agent_client.h - UCLIENT's side of the control channel to the DAEMON.
 *
 * Carries the ch_assign notification: "this client socket is waiting on this
 * statement". The daemon answers here with a status, but the response payload
 * itself arrives by a different route -- written into an agent_pipe and
 * redirected by KCLIENT into this process's own socket receive queue.
 *
 * That split is deliberate. If the payload came back over this control
 * socket, a client parked in epoll_wait() on its MySQL fd would never wake,
 * because nothing would have made that fd readable. Routing it through the
 * redirect is what lets an event-loop client be served at all.
 */
#ifndef VALKEY_EBPF_CACHE_AGENT_CLIENT_H
#define VALKEY_EBPF_CACHE_AGENT_CLIENT_H

#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "kclient.h"
}

namespace cache {

struct AgentVerdict {
	uint8_t status = AGENT_CACHE_ERROR;
	uint32_t length = 0; /* payload bytes the daemon put into our socket */
};

class AgentClient {
public:
	/* Lazily connects. Returns false when the daemon is unreachable, in
	 * which case the caller must behave as though caching is off. */
	bool connect(const std::string &path);

	bool healthy() const
	{
		return fd_ >= 0;
	}

	void disconnect();

	/* Ask the daemon about `sql` for the connection identified by `client`.
	 * Blocks until the verdict arrives. By the time this returns, any
	 * mini-protocol bytes are already queued on the client's socket. */
	bool ask(const sock_key &client, const std::string &sql, AgentVerdict &out);

	/* Hand a freshly fetched response back for storage, after a
	 * WRITE_THROUGH verdict. */
	bool store(const std::string &sql, const std::vector<uint8_t> &blob);

private:
	int fd_ = -1;
	std::string path_;
};

} // namespace cache

#endif /* VALKEY_EBPF_CACHE_AGENT_CLIENT_H */
