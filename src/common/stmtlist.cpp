// SPDX-License-Identifier: GPL-2.0
#include "common/stmtlist.h"

#include <fstream>

namespace bncl {
namespace {

/* Trim both ends. Leading whitespace is stripped so an indented line in the
 * file matches the statement a client actually sends; trailing whitespace and
 * CR are stripped because a file edited on Windows would otherwise produce
 * entries that can never match anything, with no visible reason. */
std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");

    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

} // namespace

void StmtList::add(const std::string &sql) {
    if (sql.empty()) {
        return;
    }
    /* Duplicates in the file are harmless but should not be reported twice
     * or seeded twice. */
    if (index.insert(sql).second) {
        stmts.push_back(sql);
    }
}

bool StmtList::load(const std::string &path, std::string &err) {
    std::ifstream in(path);

    if (!in) {
        err = "cannot open " + path;
        return false;
    }

    std::string line;

    while (std::getline(in, line)) {
        std::string t = trim(line);

        if (t.empty() || t[0] == '#') {
            continue;
        }
        add(t);
    }
    return true;
}

bool StmtList::contains(std::string_view sql) const {
    /* Heterogeneous lookup would avoid this allocation, but it needs a
     * transparent hash and this is not on the hot path -- the hot path is
     * the BPF-side map, not this. */
    return index.find(std::string(sql)) != index.end();
}

} // namespace bncl
