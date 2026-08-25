#!/usr/bin/env python3
"""dashboard.py - latency triage UI on top of agent's JSONL stream.

Launches build/agent as a subprocess, reads its correlated
request/response JSONL, and aggregates per-statement latency stats in
memory. The web UI it serves lets you see which exact statements are slow
right now and, with one click, add one to the reroute list with a TTL --
which rewrites config/reroute.list and sends agent SIGHUP to pick it
up, exactly like editing the file by hand and reloading would.

config/reroute.json is the structured, persistent source of truth for what
this dashboard manages (statement text, when it was added, its TTL);
config/reroute.list is *derived* from it and regenerated on every change --
do not hand-edit reroute.list while this is running, it will be overwritten
on the next add/remove/expiry sweep. Usage statistics per entry are not
tracked by the BPF layer per-entry; they are counted here instead, from the
"rerouted": true events already flowing through the JSONL stream, so no
changes to agent or the BPF program were needed for that part.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

from flask import Flask, jsonify, request, send_from_directory

APP_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(APP_DIR)
STATIC_DIR = os.path.join(APP_DIR, "static")

# Must match MAX_QUERY_LEN in bpf/proto.h -- the reroute-list key size
# the BPF program compares against. Duplicated here rather than shared
# because there is no C/Python header bridge in this project; a statement
# longer than this can never be added to the list regardless of what this
# script does, so it is worth rejecting early with a clear reason.
MAX_QUERY_LEN = 512

HOUSEKEEPING_INTERVAL_S = 2
PENDING_REQUEST_TTL_S = 30  # GC requests that never got a correlated response


@dataclass
class QueryStats:
	sql: str
	count: int = 0
	rerouted_count: int = 0
	total_latency_ms: float = 0.0
	max_latency_ms: float = 0.0
	min_latency_ms: float | None = None
	last_latency_ms: float = 0.0
	last_seen: float = field(default_factory=time.time)
	last_comm: str = ""

	def record(self, latency_ms: float, rerouted: bool, wall: float | None, comm: str) -> None:
		self.count += 1
		if rerouted:
			self.rerouted_count += 1
		self.total_latency_ms += latency_ms
		self.max_latency_ms = max(self.max_latency_ms, latency_ms)
		self.min_latency_ms = latency_ms if self.min_latency_ms is None else min(self.min_latency_ms, latency_ms)
		self.last_latency_ms = latency_ms
		self.last_seen = wall or time.time()
		self.last_comm = comm

	def to_dict(self) -> dict:
		return {
			"sql": self.sql,
			"count": self.count,
			"rerouted_count": self.rerouted_count,
			"avg_ms": self.total_latency_ms / self.count if self.count else 0.0,
			"max_ms": self.max_latency_ms,
			"min_ms": self.min_latency_ms or 0.0,
			"last_ms": self.last_latency_ms,
			"last_seen": self.last_seen,
			"last_comm": self.last_comm,
		}


class State:
	def __init__(self) -> None:
		self.lock = threading.Lock()
		self.stats_by_sql: dict[str, QueryStats] = {}
		# keyed by req_ts_ns, holds the request until its response arrives
		self.pending: dict[int, dict] = {}

	def handle_event(self, ev: dict) -> None:
		kind = ev.get("kind")
		req_ts = ev.get("req_ts_ns")
		if req_ts is None:
			return

		if kind == "request":
			with self.lock:
				self.pending[req_ts] = {
					"sql": ev.get("sql", ""),
					"rerouted": bool(ev.get("rerouted")),
					"comm": ev.get("comm", ""),
					"queued_at": time.time(),
				}
			return

		if kind != "response":
			return

		with self.lock:
			req = self.pending.pop(req_ts, None)
			if req is None or not req["sql"]:
				return
			latency_ms = (ev.get("ts_ns", req_ts) - req_ts) / 1e6
			if latency_ms < 0:
				return
			st = self.stats_by_sql.setdefault(req["sql"], QueryStats(req["sql"]))
			st.record(latency_ms, req["rerouted"], ev.get("wall"), req["comm"])

	def sweep_stale_pending(self) -> None:
		cutoff = time.time() - PENDING_REQUEST_TTL_S
		with self.lock:
			stale = [k for k, v in self.pending.items() if v["queued_at"] < cutoff]
			for k in stale:
				del self.pending[k]

	def snapshot_queries(self) -> list[dict]:
		with self.lock:
			return [st.to_dict() for st in self.stats_by_sql.values()]

	def rerouted_count_for(self, sql: str) -> int:
		with self.lock:
			st = self.stats_by_sql.get(sql)
			return st.rerouted_count if st else 0


class RerouteConfig:
	"""Structured, persistent reroute list -- config/reroute.json is the
	source of truth; config/reroute.list is regenerated from it on every
	change and agent is signaled to reload."""

	def __init__(self, json_path: str, list_path: str, reload_cb) -> None:
		self.json_path = json_path
		self.list_path = list_path
		self.reload_cb = reload_cb
		self.lock = threading.Lock()
		if not os.path.exists(self.json_path):
			self._save([])

	def _load(self) -> list[dict]:
		try:
			with open(self.json_path, encoding="utf-8") as fh:
				return json.load(fh).get("entries", [])
		except (FileNotFoundError, json.JSONDecodeError):
			return []

	def _save(self, entries: list[dict]) -> None:
		with open(self.json_path, "w", encoding="utf-8") as fh:
			json.dump({"entries": entries}, fh, indent=2)
			fh.write("\n")

	def _regenerate_list_file(self, entries: list[dict]) -> None:
		with open(self.list_path, "w", encoding="utf-8") as fh:
			fh.write(
				"# Auto-generated by app/dashboard.py from config/reroute.json.\n"
				"# Do not hand-edit while the dashboard is running -- this file is\n"
				"# regenerated on every add/remove/TTL-expiry and your changes would\n"
				"# be silently overwritten. Manage entries via the web UI, or stop\n"
				"# the dashboard first if you want to edit this by hand.\n\n"
			)
			for e in entries:
				fh.write(e["sql"] + "\n")
		self.reload_cb()

	def list(self, hit_counter) -> list[dict]:
		now = time.time()
		out = []
		for e in self._load():
			expires_at = (e["added_at"] + e["ttl_seconds"]) if e.get("ttl_seconds") else None
			out.append({
				**e,
				"hit_count": hit_counter(e["sql"]),
				"expires_at": expires_at,
				"seconds_remaining": (expires_at - now) if expires_at else None,
			})
		return out

	def add(self, sql: str, ttl_seconds: float | None) -> None:
		with self.lock:
			entries = [e for e in self._load() if e["sql"] != sql]
			entries.append({"sql": sql, "added_at": time.time(), "ttl_seconds": ttl_seconds})
			self._save(entries)
			self._regenerate_list_file(entries)

	def remove(self, sql: str) -> None:
		with self.lock:
			entries = [e for e in self._load() if e["sql"] != sql]
			self._save(entries)
			self._regenerate_list_file(entries)

	def sync(self) -> None:
		"""Push whatever is currently in config/reroute.json out to
		reroute.list and reload agent, without changing any entry.
		Used at startup in case the two files had drifted (e.g. reroute.list
		was hand-edited the last time the dashboard was stopped)."""
		with self.lock:
			self._regenerate_list_file(self._load())

	def sweep_expired(self) -> None:
		with self.lock:
			entries = self._load()
			now = time.time()
			kept = [
				e for e in entries
				if not e.get("ttl_seconds") or (now - e["added_at"]) < e["ttl_seconds"]
			]
			if len(kept) != len(entries):
				self._save(kept)
				self._regenerate_list_file(kept)


class AgentProcess:
	"""Owns the agent subprocess: launches it, reads its JSONL
	stdout into `state`, and can signal it to reload the list file."""

	def __init__(self, binary: str, reroute_list: str, state: State) -> None:
		self.binary = binary
		self.reroute_list = reroute_list
		self.state = state
		self.proc: subprocess.Popen | None = None

	def start(self) -> None:
		if not os.path.isfile(self.binary):
			print(f"dashboard: {self.binary} not found -- run `make` first", file=sys.stderr)
			sys.exit(1)
		self.proc = subprocess.Popen(
			[self.binary, "--reroute-file", self.reroute_list],
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
			bufsize=1,
			cwd=REPO_ROOT,
		)
		threading.Thread(target=self._read_stdout, daemon=True).start()
		threading.Thread(target=self._read_stderr, daemon=True).start()

	def _read_stdout(self) -> None:
		for line in self.proc.stdout:
			line = line.strip()
			if not line:
				continue
			try:
				ev = json.loads(line)
			except json.JSONDecodeError:
				continue
			self.state.handle_event(ev)

	def _read_stderr(self) -> None:
		for line in self.proc.stderr:
			print(f"[agent] {line.rstrip()}", file=sys.stderr, flush=True)

	def reload(self) -> None:
		if self.proc and self.proc.poll() is None:
			self.proc.send_signal(signal.SIGHUP)

	def stop(self) -> None:
		if self.proc and self.proc.poll() is None:
			self.proc.send_signal(signal.SIGTERM)
			try:
				self.proc.wait(timeout=5)
			except subprocess.TimeoutExpired:
				self.proc.kill()


def make_arg_parser(**kwargs) -> argparse.ArgumentParser:
	if sys.version_info >= (3, 14):
		kwargs["color"] = False
	return argparse.ArgumentParser(**kwargs)


def create_app(reroute_proc: AgentProcess, state: State, cfg: RerouteConfig) -> Flask:
	app = Flask(__name__, static_folder=None)

	@app.route("/")
	def index():
		return send_from_directory(STATIC_DIR, "index.html")

	@app.route("/api/queries")
	def api_queries():
		rows = state.snapshot_queries()
		rows.sort(key=lambda r: r["max_ms"], reverse=True)
		return jsonify(rows)

	@app.route("/api/reroute")
	def api_reroute_list():
		return jsonify(cfg.list(state.rerouted_count_for))

	@app.route("/api/reroute/add", methods=["POST"])
	def api_reroute_add():
		body = request.get_json(force=True, silent=True) or {}
		sql = (body.get("sql") or "").strip()
		ttl = body.get("ttl_seconds")
		if not sql:
			return jsonify({"error": "sql is required"}), 400
		if len(sql.encode("utf-8")) > MAX_QUERY_LEN - 1:
			return jsonify({
				"error": f"statement too long ({len(sql.encode('utf-8'))} bytes > "
					 f"{MAX_QUERY_LEN - 1}); it could never match on the wire"
			}), 400
		if ttl is not None:
			try:
				ttl = float(ttl)
				if ttl <= 0:
					raise ValueError
			except (TypeError, ValueError):
				return jsonify({"error": "ttl_seconds must be a positive number or null"}), 400
		cfg.add(sql, ttl)
		return jsonify({"ok": True})

	@app.route("/api/reroute/remove", methods=["POST"])
	def api_reroute_remove():
		body = request.get_json(force=True, silent=True) or {}
		sql = (body.get("sql") or "").strip()
		if not sql:
			return jsonify({"error": "sql is required"}), 400
		cfg.remove(sql)
		return jsonify({"ok": True})

	return app


def housekeeping_loop(state: State, cfg: RerouteConfig) -> None:
	while True:
		time.sleep(HOUSEKEEPING_INTERVAL_S)
		state.sweep_stale_pending()
		cfg.sweep_expired()


def main() -> int:
	ap = make_arg_parser(description=__doc__)
	ap.add_argument("--host", default="0.0.0.0", help="dashboard HTTP bind address")
	ap.add_argument("--port", type=int, default=8080, help="dashboard HTTP port")
	ap.add_argument("--agent-binary", default=os.path.join(REPO_ROOT, "build", "agent"))
	ap.add_argument("--reroute-list", default=os.path.join(REPO_ROOT, "config", "reroute.list"))
	ap.add_argument("--reroute-json", default=os.path.join(REPO_ROOT, "config", "reroute.json"))
	args = ap.parse_args()

	state = State()
	reroute_proc = AgentProcess(args.agent_binary, args.reroute_list, state)
	cfg = RerouteConfig(args.reroute_json, args.reroute_list, reroute_proc.reload)

	reroute_proc.start()
	atexit.register(reroute_proc.stop)
	cfg.sync()

	threading.Thread(target=housekeeping_loop, args=(state, cfg), daemon=True).start()

	app = create_app(reroute_proc, state, cfg)
	print(f"dashboard: http://{args.host}:{args.port}  (Ctrl-C to stop)", flush=True)
	app.run(host=args.host, port=args.port, threaded=True)
	return 0


if __name__ == "__main__":
	sys.exit(main())
