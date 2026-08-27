# CLAUDE.md

## Project: Query Cache

This project is a transparent query cache. See README for more information.
See architecture.txt for implementation details and design.

## Code Generation Guidlines:

- Use `#pragma once` rather than include guards for C++
- Prefer smaller and shorter names for variables and functions
- Prefer repeating code rather than being "clever" unless otherwise instructed
- Code should have more of a C flavor, even in C++.
  - No trailing underscore for private members
  - Constants should be ALL_CAPS_WITH_UNDERSCORES
  - Prefer std::string_view over std::string
  - Prefer iterator begin/end over std::vector, unless being added to
  - Don't return std::string/std::vector.. user passes them as out-values to be filled
  - 
- Don't use "../" in include paths. Includes should be relative to the source
  root, which itself should be included in the include directories.
- Tests should be incremental and deterministic. They should not be "smart".
- Prefer C over C++ for simple files and tasks
- C++ standard is C++20
- Project is qcache or query cache; prefixes are qc_ for C functions that aren't static
- Avoid 'using namespace'