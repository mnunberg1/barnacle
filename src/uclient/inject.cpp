// SPDX-License-Identifier: GPL-2.0
/*
 * inject.cpp - put the agent into a process that is already running.
 *
 * This is the property LD_PRELOAD cannot provide: it only takes effect if the
 * environment was set before exec, so it can never reach a process that is
 * already up and serving traffic. Frida's injector attaches to a live pid and
 * loads a shared object into it -- the same call bpftime's `attach` makes.
 *
 * Usage:  ./build/qcinject <pid> [/path/to/libqcagent.so]
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

#include <frida-core.h>

int main(int argc, char **argv)
{
	FridaInjector *injector;
	GError *error = NULL;
	guint id;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <pid> [agent.so]\n", argv[0]);
		return 1;
	}

	guint pid = (guint)atoi(argv[1]);
	std::string so = argc > 2 ? argv[2] : "./build/libqcagent.so";
	char abs[4096];

	if (!realpath(so.c_str(), abs)) {
		fprintf(stderr, "inject: cannot resolve %s\n", so.c_str());
		return 1;
	}

	frida_init();
	injector = frida_injector_new();

	/* The agent's constructor does the rest: it maps the arena, opens the
	 * statement table, and replaces the TLS entry points. */
	/* The list path travels as agent data: the target's environment is its
	 * own, so exporting QCACHE_LIST here would not reach it. */
	const char *list = getenv("QCACHE_LIST");

	id = frida_injector_inject_library_file_sync(injector, pid, abs, "qcagent_init",
						     list ? list : "", NULL, &error);
	if (error) {
		fprintf(stderr, "inject: %s\n", error->message);
		g_error_free(error);
		return 1;
	}

	printf("inject: agent loaded into pid %u (id %u)\n", pid, id);
	frida_injector_close_sync(injector, NULL, NULL);
	frida_unref(injector);
	return 0;
}
