// SPDX-License-Identifier: GPL-2.0
#include "config.h"

#include <cctype>
#include <fstream>
#include <sstream>

namespace qcache {
namespace {

std::string trim(const std::string &s)
{
	size_t a = s.find_first_not_of(" \t\r\n");
	size_t b = s.find_last_not_of(" \t\r\n");

	return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

} // namespace

bool Config::load(const std::string &path, Config &out, std::string &err)
{
	std::ifstream in(path);

	if (!in) {
		err = "cannot open " + path;
		return false;
	}

	std::string line;
	std::string section;
	int lineno = 0;

	while (std::getline(in, line)) {
		lineno++;
		std::string t = trim(line);

		if (t.empty() || t[0] == '#' || t[0] == ';') {
			continue;
		}

		if (t[0] == '[') {
			size_t close = t.find(']');

			if (close == std::string::npos) {
				err = path + ":" + std::to_string(lineno) +
				      ": unterminated section header";
				return false;
			}
			section = trim(t.substr(1, close - 1));

			/* "[target <name>]" opens a new target block. */
			if (section.rfind("target", 0) == 0) {
				Target tgt;

				tgt.name = trim(section.substr(6));
				if (tgt.name.empty()) {
					tgt.name = "target" +
						   std::to_string(out.targets.size() + 1);
				}
				out.targets.push_back(tgt);
				section = "target";
			}
			continue;
		}

		size_t eq = t.find('=');

		if (eq == std::string::npos) {
			err = path + ":" + std::to_string(lineno) + ": expected key = value";
			return false;
		}
		std::string key = trim(t.substr(0, eq));
		std::string val = trim(t.substr(eq + 1));

		if (section == "target") {
			if (out.targets.empty()) {
				err = path + ":" + std::to_string(lineno) +
				      ": key outside any [target] section";
				return false;
			}
			Target &tgt = out.targets.back();

			if (key == "comm") {
				tgt.comm = val;
			} else if (key == "cmdline") {
				tgt.cmdline = val;
			} else if (key == "container") {
				tgt.container = val;
			} else if (key == "mysql_port") {
				tgt.mysql_port = (uint16_t)std::stoi(val);
			} else if (key == "statements") {
				tgt.statements = val;
			} else if (key == "ttl") {
				tgt.ttl = std::stoi(val);
			} else {
				err = path + ":" + std::to_string(lineno) +
				      ": unknown target key '" + key + "'";
				return false;
			}
			continue;
		}

		/* Everything else is global. */
		if (key == "control_path") {
			out.control_path = val;
		} else if (key == "valkey_host") {
			out.valkey_host = val;
		} else if (key == "valkey_port") {
			out.valkey_port = (uint16_t)std::stoi(val);
		} else if (key == "libssl") {
			out.libssl_hint = val;
		} else {
			err = path + ":" + std::to_string(lineno) + ": unknown key '" +
			      key + "'";
			return false;
		}
	}

	if (out.targets.empty()) {
		err = path + ": no [target ...] sections defined";
		return false;
	}
	for (const auto &t : out.targets) {
		/* A target with no matchers would match every process on the
		 * host. Refuse it rather than attach to the whole machine. */
		if (t.matchesNothing()) {
			err = path + ": target '" + t.name +
			      "' has no comm/cmdline/container matcher; it would match "
			      "every process on the host";
			return false;
		}
	}
	return true;
}

} // namespace qcache
