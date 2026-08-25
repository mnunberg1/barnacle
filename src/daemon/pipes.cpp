// SPDX-License-Identifier: GPL-2.0
#include "pipes.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>

namespace qcd {

bool sockKeyOf(int fd, sock_key &out)
{
	struct sockaddr_in local {};
	struct sockaddr_in remote {};
	socklen_t l = sizeof(local), r = sizeof(remote);

	if (getsockname(fd, (struct sockaddr *)&local, &l) != 0) {
		return false;
	}
	if (getpeername(fd, (struct sockaddr *)&remote, &r) != 0) {
		return false;
	}
	memset(&out, 0, sizeof(out));
	out.sip = local.sin_addr.s_addr;
	out.dip = remote.sin_addr.s_addr;
	/* htonl(port_number), matching bpf_htonl(local_port) on the BPF side --
	 * NOT sin_port, which is only 16 bits wide. */
	out.sport = htonl(ntohs(local.sin_port));
	out.dport = htonl(ntohs(remote.sin_port));
	out.family = AF_INET;
	return true;
}

bool PipePool::makePipe(AgentPipe &p)
{
	struct sockaddr_in addr {};
	socklen_t alen = sizeof(addr);
	int cfd = -1, afd = -1;
	int one = 1;

	if (getsockname(listen_fd_, (struct sockaddr *)&addr, &alen) != 0) {
		return false;
	}

	cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (cfd < 0) {
		return false;
	}
	if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(cfd);
		return false;
	}
	afd = accept(listen_fd_, nullptr, nullptr);
	if (afd < 0) {
		close(cfd);
		return false;
	}

	/* Mini-protocol writes are tiny and latency-critical; Nagle would
	 * batch them and defeat the purpose. */
	setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(afd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	p.local_fd = cfd;
	p.peer_fd = afd;
	if (!sockKeyOf(cfd, p.skey)) {
		close(cfd);
		close(afd);
		return false;
	}
	return true;
}

bool PipePool::init(int sock_map_fd, int pipe_pairs_fd, size_t count)
{
	struct sockaddr_in addr {};

	sock_map_fd_ = sock_map_fd;
	pipe_pairs_fd_ = pipe_pairs_fd;

	listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd_ < 0) {
		return false;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0; /* any free port */
	if (bind(listen_fd_, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(listen_fd_, 64) != 0) {
		close(listen_fd_);
		listen_fd_ = -1;
		return false;
	}

	for (size_t i = 0; i < count; i++) {
		AgentPipe p;

		if (!makePipe(p)) {
			fprintf(stderr, "daemon: pipe %zu failed: %s\n", i,
				strerror(errno));
			return false;
		}
		p.key = key_serial_++;

		/* The pipe's local end must be in the sockmap for its sends to
		 * reach the sk_msg program at all. */
		if (bpf_map_update_elem(sock_map_fd_, &p.skey, &p.local_fd, BPF_ANY) !=
		    0) {
			fprintf(stderr, "daemon: sockmap register failed: %s\n",
				strerror(errno));
			close(p.local_fd);
			close(p.peer_fd);
			return false;
		}

		pipes_.push_back(p);
		AgentPipe *stored = &pipes_.back();

		by_key_[stored->key] = stored;
		free_list_.push_back(stored->key);
	}
	return true;
}

AgentPipe *PipePool::acquire(const sock_key &client)
{
	std::lock_guard<std::mutex> g(lock_);

	if (free_list_.empty()) {
		return nullptr;
	}
	uint32_t key = free_list_.back();

	free_list_.pop_back();

	auto it = by_key_.find(key);

	if (it == by_key_.end()) {
		return nullptr;
	}
	AgentPipe *p = it->second;

	/* The pairing is what turns this pipe's writes into deliveries to that
	 * client. Until it exists, redirect() passes the pipe's traffic
	 * straight through. */
	if (bpf_map_update_elem(pipe_pairs_fd_, &p->skey, &client, BPF_ANY) != 0) {
		free_list_.push_back(key);
		return nullptr;
	}
	p->in_use = true;
	return p;
}

void PipePool::release(AgentPipe *p)
{
	std::lock_guard<std::mutex> g(lock_);

	if (!p || !p->in_use) {
		return;
	}
	/* Remove the pairing before the pipe is reusable. A stale pairing
	 * would redirect the next, unrelated response into a client that is no
	 * longer waiting for one. */
	bpf_map_delete_elem(pipe_pairs_fd_, &p->skey);
	p->in_use = false;
	free_list_.push_back(p->key);
}

AgentPipe *PipePool::byKey(uint32_t key)
{
	std::lock_guard<std::mutex> g(lock_);
	auto it = by_key_.find(key);

	return it == by_key_.end() ? nullptr : it->second;
}

size_t PipePool::freeCount()
{
	std::lock_guard<std::mutex> g(lock_);

	return free_list_.size();
}

void PipePool::shutdown()
{
	std::lock_guard<std::mutex> g(lock_);

	for (auto &p : pipes_) {
		if (p.in_use) {
			bpf_map_delete_elem(pipe_pairs_fd_, &p.skey);
		}
		bpf_map_delete_elem(sock_map_fd_, &p.skey);
		if (p.local_fd >= 0) {
			close(p.local_fd);
		}
		if (p.peer_fd >= 0) {
			close(p.peer_fd);
		}
	}
	pipes_.clear();
	by_key_.clear();
	free_list_.clear();
	if (listen_fd_ >= 0) {
		close(listen_fd_);
		listen_fd_ = -1;
	}
}

} // namespace qcd
