#!/usr/bin/env python3
"""Tail the BLE capture db for new drone broadcasts.

Polls only rows newer than the last seen id (cheap, indexed) — never
rescans the backlog. Default: skip everything already in the db at
startup and only report broadcasts that come in from now on.

Usage:
  python3 watch_drones.py                    # tail only new rows
  python3 watch_drones.py --since-start      # also scan existing rows once
  python3 watch_drones.py --interval 1.0     # poll every 1.0s (default 2.0)
  python3 watch_drones.py --db PATH          # custom db path
"""

import argparse
import os
import sqlite3
import sys
import time

from find_drones import classify_packet


def open_ro(db_path: str) -> sqlite3.Connection:
    """Open db read-only so we never contend with the writer."""
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)


def get_max_id(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM ble_packets").fetchone()
    return row[0]


def fetch_new(conn: sqlite3.Connection, since_id: int):
    """Yield rows with id > since_id, ordered ascending."""
    cur = conn.execute(
        "SELECT id, ts, sdr, channel, addr, pdu_type, adv_data, rssi_dbfs, name "
        "FROM ble_packets WHERE id > ? AND crc_ok = 1 AND adv_data IS NOT NULL "
        "ORDER BY id ASC",
        (since_id,),
    )
    return cur.fetchall()


def fmt_hit(ts, sdr, channel, addr, rssi, name, pdu_type, hits) -> str:
    when = time.strftime("%H:%M:%S", time.localtime(ts))
    rssi_s = f"{rssi:+.1f}dBFS" if rssi is not None else "?"
    name_s = f' name="{name}"' if name else ""
    head = (f"\n\033[1;31m[DRONE]\033[0m {when}  "
            f"\033[1m{addr}\033[0m  {sdr} ch{channel}  {rssi_s}  "
            f"{pdu_type}{name_s}")
    body = "\n".join(f"          \033[33m{cat}\033[0m: {detail}"
                     for cat, detail in hits)
    return head + "\n" + body


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "ble_scan.db"))
    ap.add_argument("--interval", type=float, default=2.0,
                    help="poll interval in seconds (default 2.0)")
    ap.add_argument("--since-start", action="store_true",
                    help="also process rows that existed at startup")
    ap.add_argument("--quiet", action="store_true",
                    help="no periodic 'alive' status line")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"db not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    conn = open_ro(args.db)

    if args.since_start:
        last_id = 0
        print(f"Scanning entire db {args.db} for drones, then tailing...",
              flush=True)
    else:
        last_id = get_max_id(conn)
        print(f"Watching {args.db} from id={last_id} (Ctrl-C to stop)",
              flush=True)

    seen_pkts = 0
    drone_hits = 0
    last_status = time.time()
    STATUS_EVERY = 30.0   # one status line every 30s if nothing happened

    try:
        while True:
            rows = fetch_new(conn, last_id)
            for (rid, ts, sdr, channel, addr, pdu_type, adv_data,
                 rssi, name) in rows:
                last_id = rid
                seen_pkts += 1
                hits = classify_packet(addr or "", bytes(adv_data))
                if hits:
                    drone_hits += 1
                    print(fmt_hit(ts, sdr, channel, addr, rssi, name,
                                  pdu_type, hits), flush=True)

            now = time.time()
            if not args.quiet and now - last_status >= STATUS_EVERY:
                when = time.strftime("%H:%M:%S", time.localtime(now))
                print(f"[{when}] tailing — {seen_pkts} pkts scanned, "
                      f"{drone_hits} drone hits", flush=True)
                last_status = now

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nStopped. Scanned {seen_pkts} packets, found {drone_hits} "
              f"drone broadcast(s).")


if __name__ == "__main__":
    main()
