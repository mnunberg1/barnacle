No, you're right. But in this case, we need to trace both send and recv.. figure out if there is a way to correlate
requests and responses from mysqld. Oh, the main logic tracking should be done in C++ outside the kernel. The eBPF code
should intercept read/write/sendto/recvfrom/etc.

You should also maintain a persistent storage, for now it could just be a simple file, which indicates
which queries to intercept and reroute.

When SEND/WRITE/etc is detected, assuming it is a valid request/packet, do the following:

Check the reroute list. If the query is not in the list, exit.
If the query is in the list, replace the outgoing packet's statement with `-- SELECT 0`,

Because the MySQL is a FIFO protocol, we cannot just discard packets that we can't handle, but rather need to parse
them in order to maintain state.

We will also need to keep track of the host/port of the connection, and/or the fd or skb, depending on what is
necessary in order to correlate requests and responses.

When we send a SELECT 0, we may also need to pad or otherwise pack the rest of the buffer so that the packet
still remains valid. As far as I know, we can't override a system call's arguments.

We have enter/exit pairs, so upon the exit pair (i.e. after the kernel already copied the buffer) we should
reset the buffer state to its original -- just in case applications still refer to it for something else.