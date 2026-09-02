// SPDX-License-Identifier: GPL-2.0
/*
 * inject.cpp - put the agent into a process that is already running.
 *
 * This is the property LD_PRELOAD cannot provide: it only takes effect if the
 * environment was set before exec, so it can never reach a process that is
 * already up and serving traffic. Frida's injector attaches to a live pid and
 * loads a shared object into it -- the same call bpftime's `attach` makes.
 *
 * Usage:  ./build/bncl-inject <pid> [agent.so] [data]
 *
 * `data` is handed to bncl_agent_init. Normally it is the path to the statement
 * list; the literal string "detach" tells an agent already in the process to
 * put the entry points back. That is why this runs more than once against the
 * same pid, and why the second run is not a mistake.
 *
 * --- paths are the TARGET's, not ours -------------------------------------
 *
 * Both paths below are opened by the target process, in the target's mount
 * namespace. When the target is in another container that is a different
 * filesystem from this one, and a path that exists here may well not exist
 * there. So an absolute path is passed through untouched -- the caller is
 * telling us what the target will see, and resolving it against our own root
 * would either fail or, worse, silently name a different file.
 *
 * Relative paths are resolved here, which is right for the common case of
 * injecting into a process that shares our filesystem.
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
        fprintf(stderr, "usage: %s <pid> [agent.so] [data]\n", argv[0]);
        return 1;
    }

    guint pid = (guint)atoi(argv[1]);
    std::string so = argc > 2 ? argv[2] : "./build/libbnclagent.so";
    std::string path;

    if (so[0] == '/') {
        path = so;
    }
    else {
        char abs[4096];

        if (!realpath(so.c_str(), abs)) {
            fprintf(stderr, "inject: cannot resolve %s\n", so.c_str());
            return 1;
        }
        path = abs;
    }

    /* The list path travels as agent data: the target's environment is its
     * own, so exporting BARNACLE_LIST here would not reach it. */
    const char *env = getenv("BARNACLE_LIST");
    std::string data = argc > 3 ? argv[3] : (env ? env : "");

    frida_init();
    injector = frida_injector_new();

    /* The agent's constructor does the rest: it maps the arena, opens the
     * statement table, and replaces the TLS entry points. */
    id = frida_injector_inject_library_file_sync(injector, pid, path.c_str(), "bncl_agent_init",
                                                 data.c_str(), NULL, &error);
    if (error) {
        fprintf(stderr, "inject: %s\n", error->message);
        g_error_free(error);
        return 1;
    }

    printf("inject: %s pid %u (id %u)\n", data == "detach" ? "detached from" : "agent loaded into",
           pid, id);
    frida_injector_close_sync(injector, NULL, NULL);
    frida_unref(injector);
    return 0;
}
