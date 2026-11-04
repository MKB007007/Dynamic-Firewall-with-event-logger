#!/usr/bin/env python3
"""TCP security-event logging server for the POX SDN firewall.

The POX controller opens one TCP connection per event, sends one newline-
terminated log record, and closes the connection. This server appends each
record to security_events.log and prints it to the terminal.
"""

import os
import socketserver
import threading

BIND_HOST = os.environ.get("LOGGER_BIND_HOST", "0.0.0.0")
LOGGER_PORT = int(os.environ.get("LOGGER_PORT", "7000"))
LOG_FILE = os.environ.get(
    "LOGGER_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_events.log"),
)

_file_lock = threading.Lock()


class LogRequestHandler(socketserver.StreamRequestHandler):
    """Receive one event line from each TCP connection."""

    def handle(self):
        # Limit a single event to 16 KiB to avoid unbounded reads.
        raw_line = self.rfile.readline(16 * 1024 + 1)
        if not raw_line:
            return

        if len(raw_line) > 16 * 1024:
            print("[LOGGER] Rejected oversized event", flush=True)
            return

        event = raw_line.decode("utf-8", errors="replace")
        if not event.endswith("\n"):
            event += "\n"

        # Multiple clients may log simultaneously; serialize file writes.
        try:
            with _file_lock:
                with open(LOG_FILE, "a", encoding="utf-8") as log_file:
                    log_file.write(event)
                    log_file.flush()
            print(event, end="", flush=True)
        except OSError as exc:
            print("[LOGGER] Could not write event to {!r}: {}".format(LOG_FILE, exc),
                  flush=True)


class ThreadedLogServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    log_dir = os.path.dirname(os.path.abspath(LOG_FILE))
    if not os.path.isdir(log_dir):
        os.makedirs(log_dir)

    with ThreadedLogServer((BIND_HOST, LOGGER_PORT), LogRequestHandler) as server:
        print("Logging server listening on {}:{}".format(BIND_HOST, LOGGER_PORT),
              flush=True)
        print("Appending events to: {}".format(LOG_FILE), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nLogging server stopped.", flush=True)


if __name__ == "__main__":
    main()
