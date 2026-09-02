// SPDX-License-Identifier: GPL-2.0
#pragma once
/*
 * stmtlist.h - the administrator's list of cacheable statements.
 *
 * The whole configuration surface of this cache, per the goals: which queries
 * to cache, and for how long. Everything else is discovered.
 *
 * Matching is exact bytes. Not a prefix, and not normalized -- `WHERE id = 5`
 * is a prefix of `WHERE id = 55`, so prefix matching would serve one query's
 * rows for another. Normalization (whitespace, parameter substitution) is a
 * real feature but a different one, and it changes what a cache key means.
 */

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace bncl {

class StmtList {
public:
    /* Read a list file: one statement per line, `#` comments and blank
     * lines ignored. Returns false and fills `err` if the file cannot be
     * opened -- an unreadable list is a configuration error, not an empty
     * list, and silently caching nothing is the worst way to report it. */
    bool load(const std::string &path, std::string &err);

    /* For tests and for callers that build a list without a file. */
    void add(const std::string &sql);

    bool contains(std::string_view sql) const;

    size_t size() const
    {
        return stmts.size();
    }
    bool empty() const
    {
        return stmts.empty();
    }
    const std::vector<std::string> &all() const
    {
        return stmts;
    }

private:
    /* Both, deliberately: `all()` preserves file order so the daemon can
     * report and seed predictably, while the set answers the hot question. */
    std::vector<std::string> stmts;
    std::unordered_set<std::string> index;
};

} // namespace bncl
