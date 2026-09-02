# CLAUDE.md

## Project: Barnacle

Barnacle is a transparent query cache. See README for more information.
See architecture.txt for implementation details and design.

## Code Generation Guidlines:

- Use `#pragma once` rather than include guards for C++
- Prefer smaller and shorter names for variables and functions
- Prefer repeating code rather than being "clever" unless otherwise instructed
- Code should have more of a C flavor, even in C++.
  - No trailing underscore for private members
  - Constants should be `ALL_CAPS_WITH_UNDERSCORES`
  - Prefer `std::string_view` over std::string
  - Prefer iterator begin/end over std::vector, unless being added to
  - Don't return std::string/std::vector.. user passes them as out-values to be filled
  - When casting to structs in C++, don't use the full `struct XXX`
  - 
- Don't use "../" in include paths. Includes should be relative to the source
  root, which itself should be included in the include directories.
- Tests should be incremental and deterministic. They should not be "smart".
- Prefer C over C++ for simple files and tasks
- C++ standard is C++20
- Project is `barnacle`; the internal prefix is `bncl`
  - `BNCL_` for macros, `bncl_` for C functions and structs that aren't static
  - namespaces: `bncl` (common), `bncl::daemon` (daemon), `bncl::agent` (injected agent)
  - built components are `bncl-daemon`, `bncl-inject`, `libbnclagent.so`; the
    command line itself is just `barnacle`
  - user-visible paths are spelled out: `/run/barnacle`, `/sys/fs/bpf/barnacle`,
    and the Valkey key prefix is `bncl:`
- Avoid 'using namespace'
- Don't forget to generate/update IDE shims whenever you add/modify functions
    unavailable on mac
- Use (4) spaces instead of tabs
- don't touch architecture.txt. You can read it, but never modify it.
- global `extern` variables end in `_g` rather than beginning with `g_`
- global `static` variables end in `_s` rather than beginning with `s_`
- file scope variables should either be `static` or `extern`
- check CLAUDE.md for updates whenever you modify code.
- C++ integral casts/coalescing should use `static_cast` if at all necessry.