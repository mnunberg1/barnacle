# Valkey Query Cache

This project aims to provide a turnkey query cache allowing system administrators
to quickly accelerate slow DB queries without explicitly configuring a cache or
maintaining more infrastructure.

The only configuration required is:

1. Location of the cache
2. How to identify outbound DB connections
3. Which queries to optimize

Strictly speaking, however, all except #1 can be inferred through heuristics

## Setup and building

There is ONE daemon that does need to run, although it is entirely self-contained,
not requiring any ports or permissions. It simply serves to coordinate and schedule
cache notification [...]

One dependency is frida-gum, which for the time being does the heavy lifting of
binary injection and patching at a few points in the program. This is needed in
order to intercept I/O of applications using OpenSSL without having to run a full-
blown man-in-the-middle proxy. Instead, we intercept calls to the SSL functions
themselves, and determine whether or not they involve caching or not.

