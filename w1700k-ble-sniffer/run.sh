#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# w1700k-ble-sniffer: check the W1700K receiver, build, and run the sniffer into the sqlite sink
# (optionally the web UI). Ctrl-C stops everything. See ./run.sh --help and README.md.
#
# Never changes the radio unless --configure is given. Reads `w1700k status` and the stream
# service's shared-memory header only.
#
# Test hooks (environment): W1700K_CTL (an executable used instead of the w1700k CLI),
# W1700K_SPECTRUM (none | HOST:PORT: skip looking for a running w1700k-spectrum),
# W1700K_SERVE_PIDS (with W1700K_SPECTRUM=none), W1700K_BLE_BIN (sniffer binary; skips make),
# W1700K_BLE_LOGS (log directory), PYTHON (default /usr/bin/python3).
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
W1700K_REPO=${W1700K_REPO:-$HOME/Software/w1700k-sdr}
BIN=${W1700K_BLE_BIN:-$HERE/build/w1700k-ble}
LOGS=${W1700K_BLE_LOGS:-$HERE/logs}
PY=${PYTHON:-/usr/bin/python3}
[ -x "$PY" ] || PY=$(command -v python3)

usage() {
    cat <<EOF
usage: ./run.sh [options] [-- extra w1700k-ble arguments]

Checks that w1700k-stream is alive and that the receiver covers 2401-2481 MHz (band 0, inside
LO +- 0.6 * rate/2), builds if needed, then runs
  build/w1700k-ble --lo <status lo_hz> --rate <status sample_rate> | sink/w1700k_ble_sink.py
and polls the receiver: if its LO or rate changes, the sniffer is restarted with the new values.

receiver
  --configure        first set the recommended BLE setup: band 0, 160 Msps, LO 2441 MHz (and
                     start the stream). Through the running w1700k-spectrum's own control channel
                     if there is one (it takes over the spectrum page's connection; click the page
                     to take it back), else with the w1700k CLI.
  --force            run even if 2401-2481 MHz does not fit (e.g. 80 Msps: best effort)
  --shm NAME         stream shared memory (default /w1700k-stream)
  --poll S           seconds between receiver checks (default 10)
  --no-watch         exit when the receiver changes instead of restarting the sniffer

output
  --db PATH          sqlite db (default ./ble_w1700k.db)
  --shared-db        use ../simple-plutoble-scanner/ble_scan.db (merge with Pluto/bladeRF rows)
  --pcap             also write logs/ble-<time>.pcap (Wireshark, LINKTYPE 256)
  --all              keep CRC-failed packets (sniffer --emit-bad-crc, sink --all)
  --skip-empty       do not store empty data PDUs (still counted)
  --dashboard        print ble_scan_dashboard.py's lines on stdout:
                       ./run.sh --dashboard | ../simple-plutoble-scanner/ble_scan_dashboard.py
  --web              also serve the web UI (sink/ble_web.py), http://127.0.0.1:8075/
  --web-host H, --web-port P

sniffer (passed to build/w1700k-ble)
  --threads N, --stats S (default 5), --channels all|adv|LIST, --threshold-db DB

  --no-build         do not run make
  --dry-run          check the receiver and print what would run; change nothing
EOF
}

say() { printf '%s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

CONFIGURE=0 FORCE=0 SHM=/w1700k-stream POLL=10 WATCH=1
DB=$HERE/ble_w1700k.db PCAP=0 ALL=0 SKIP_EMPTY=0 DASHBOARD=0
WEB=0 WEB_HOST=127.0.0.1 WEB_PORT=8075 STATS_SEC=5 BUILD=1 DRY=0
SNIFF=()
while [ $# -gt 0 ]; do
    case $1 in
        -h|--help) usage; exit 0 ;;
        --configure) CONFIGURE=1 ;;
        --force) FORCE=1 ;;
        --shm) SHM=${2:?--shm NAME}; shift ;;
        --poll) POLL=${2:?--poll S}; shift ;;
        --no-watch) WATCH=0 ;;
        --watch) WATCH=1 ;;
        --db) DB=${2:?--db PATH}; shift ;;
        --shared-db) DB=$(cd "$HERE/.." && pwd)/simple-plutoble-scanner/ble_scan.db ;;
        --pcap) PCAP=1 ;;
        --all) ALL=1 ;;
        --skip-empty) SKIP_EMPTY=1 ;;
        --dashboard) DASHBOARD=1 ;;
        --web) WEB=1 ;;
        --web-host) WEB=1; WEB_HOST=${2:?--web-host H}; shift ;;
        --web-port) WEB=1; WEB_PORT=${2:?--web-port P}; shift ;;
        --stats) STATS_SEC=${2:?--stats S}; shift ;;
        --threads|--channels|--threshold-db) SNIFF+=("$1" "${2:?$1 needs a value}"); shift ;;
        --no-build) BUILD=0 ;;
        --dry-run) DRY=1 ;;
        --) shift; SNIFF+=("$@"); break ;;
        *) usage >&2; die "unknown option $1" ;;
    esac
    shift
done
case $DB in /*) ;; *) DB=$PWD/$DB ;; esac

RUNDIR=$(mktemp -d "${TMPDIR:-/tmp}/w1700k-ble.XXXXXX") || die "mktemp failed"
FIFO=$RUNDIR/packets
BIN_PID='' SINK_PID='' WEB_PID='' SLEEP_PID='' STATSLOG='' RUN_CONFIG='' RUN_SHM_PID=''

radio() { "$PY" "$HERE/sink/w1700k_radio.py" "$@"; }

ctl() {
    if [ -n "${W1700K_CTL:-}" ]; then
        "$W1700K_CTL" "$@"
    else
        local py=$W1700K_REPO/.venv/bin/python
        [ -x "$py" ] || py=python3
        "$py" "$W1700K_REPO/host/bin/w1700k" "$@"
    fi
}

# ---- the receiver --------------------------------------------------------------------------

# Sets SHM_ALIVE, SHM_PID, SHM_RATE, ... (w1700k_radio.py shm). Returns its status.
read_shm() {
    local out rc
    out=$(radio shm --name "$SHM")
    rc=$?
    SHM_ALIVE=0 SHM_PID='' SHM_RATE=0 SHM_ERROR=''
    eval "$out"
    return $rc
}

# Sets LO_HZ, RATE, BAND, RUNNING, USABLE, RECOMMENDED, WHY (w1700k_radio.py check); its
# warnings go to $RUNDIR/check.err. Returns 0 if usable.
read_receiver() {
    local status out rc force=''
    [ $FORCE = 1 ] && force=--force
    USABLE=0 WHY='' LO_HZ='' RATE='' BAND='' RUNNING=0 RECOMMENDED=0
    : >"$RUNDIR/check.err"
    if ! status=$(ctl status 2>"$RUNDIR/status.err"); then
        WHY="w1700k status failed: $(tail -n 3 "$RUNDIR/status.err" | tr '\n' ' ')"
        return 4
    fi
    out=$(printf '%s\n' "$status" | radio check $force 2>"$RUNDIR/check.err")
    rc=$?
    eval "$out"
    return $rc
}

describe() { echo "band $BAND, LO $LO_HZ Hz, $(( RATE / 1000000 )) Msps"; }

shm_problem() {
    if [ -n "$SHM_ERROR" ]; then
        echo "w1700k-stream is not running ($SHM_ERROR): start the receiver with $W1700K_REPO/host/bin/w1700k-mac"
    else
        echo "w1700k-stream's heartbeat in $SHM is stale (pid $SHM_PID not running?): restart it with $W1700K_REPO/host/bin/w1700k-mac"
    fi
}

configure() {
    if [ $USABLE = 1 ] && [ "$RECOMMENDED" = 1 ] && [ "$RUNNING" = 1 ]; then
        say "--configure: the receiver already has the recommended setup ($(describe))"
        return 0
    fi
    local SPECTRUM_PID='' SPECTRUM_LISTEN='' SPECTRUM_CONTROLLER=0 SERVE_PIDS=''
    if [ -n "${W1700K_SPECTRUM:-}" ]; then
        if [ "$W1700K_SPECTRUM" != none ]; then
            SPECTRUM_PID=env SPECTRUM_LISTEN=$W1700K_SPECTRUM SPECTRUM_CONTROLLER=1
        else
            SERVE_PIDS=${W1700K_SERVE_PIDS:-}
        fi
    else
        eval "$(radio spectrum-find)"
    fi
    if [ -n "$SPECTRUM_PID" ] && [ "$SPECTRUM_CONTROLLER" = 1 ]; then
        say "--configure: through the running w1700k-spectrum at $SPECTRUM_LISTEN: band 0, 160 Msps, LO 2441 MHz"
        if [ $DRY = 1 ]; then say "(dry run: not sent)"; return 0; fi
        warn "this takes over the spectrum page's connection: the open page shows that another browser took over; click it to take the page back"
        radio spectrum-configure --spectrum "$SPECTRUM_LISTEN" ||
            die "--configure through the spectrum server failed (see above); set it in the spectrum page instead: Band 0, Sample rate 160 Msps, Apply, then LO 2441 MHz"
        return 0
    fi
    if [ -n "$SERVE_PIDS" ]; then
        die "--configure: a 'w1700k serve' controller is running (pid $SERVE_PIDS) without a w1700k-spectrum this script can reach; it keeps the receiver state in memory and would not see a CLI change. Configure through whatever runs it, or stop it first."
    fi
    if [ -n "$SPECTRUM_PID" ]; then
        warn "w1700k-spectrum (pid $SPECTRUM_PID) runs with --no-controller: its axis labels will not follow a CLI change"
    fi
    say "--configure: no w1700k-spectrum with a controller is running: using the w1700k CLI: band 0 --rate 160 --lo 2441M"
    warn "a CLI change is not seen by a spectrum server started earlier, and the stream header's radio_sample_rate (written only by the spectrum server) may be stale: run.sh passes --rate to the sniffer explicitly"
    if [ $DRY = 1 ]; then say "(dry run: not run)"; return 0; fi
    ctl band 0 --rate 160 --lo 2441M >/dev/null || die "w1700k band 0 --rate 160 --lo 2441M failed"
    read_receiver
    if [ "$RUNNING" != 1 ]; then
        say "--configure: starting the stream (w1700k start)"
        ctl start >/dev/null || die "w1700k start failed"
    fi
}

# ---- the pipeline --------------------------------------------------------------------------

wait_pid() {    # pid seconds: 0 once it has exited (reaped), 1 if still running after `seconds`
    local pid=$1 n=0
    [ -n "$pid" ] || return 0
    while kill -0 "$pid" 2>/dev/null; do
        [ $n -ge $(( $2 * 10 )) ] && return 1
        sleep 0.1
        n=$(( n + 1 ))
    done
    wait "$pid" 2>/dev/null
    return 0
}

sniffer_args() {
    ARGS=(--lo "$LO_HZ" --rate "$RATE" --stats "$STATS_SEC")
    [ "$SHM" != /w1700k-stream ] && ARGS+=(--shm "$SHM")
    [ $PCAP = 1 ] && ARGS+=(--pcap "$1.pcap")
    [ $ALL = 1 ] && ARGS+=(--emit-bad-crc)
    [ ${#SNIFF[@]} -gt 0 ] && ARGS+=("${SNIFF[@]}")
    SINK_ARGS=(--db "$DB" --stats-file "$1.stats.log")
    [ $ALL = 1 ] && SINK_ARGS+=(--all)
    [ $SKIP_EMPTY = 1 ] && SINK_ARGS+=(--skip-empty)
    [ $DASHBOARD = 1 ] && SINK_ARGS+=(--dashboard-lines)
    return 0
}

start_pipeline() {
    local base
    base=$LOGS/ble-$(date +%Y%m%d-%H%M%S)
    sniffer_args "$base"
    STATSLOG=$base.stats.log
    : >"$STATSLOG"
    ln -sf "$(basename "$STATSLOG")" "$LOGS/latest.stats.log"
    [ -p "$FIFO" ] || mkfifo "$FIFO" || die "mkfifo $FIFO failed"
    if [ $DASHBOARD = 1 ]; then
        "$PY" "$HERE/sink/w1700k_ble_sink.py" "${SINK_ARGS[@]}" <"$FIFO" 2>>"$base.sink.log" &
    else
        "$PY" "$HERE/sink/w1700k_ble_sink.py" "${SINK_ARGS[@]}" <"$FIFO" &
    fi
    SINK_PID=$!
    "$BIN" "${ARGS[@]}" >"$FIFO" 2>>"$STATSLOG" &
    BIN_PID=$!
    STARTED_AT=$(date +%s)
    RUN_CONFIG="$BAND $LO_HZ $RATE"
    RUN_SHM_PID=$SHM_PID
    say "w1700k-ble (pid $BIN_PID): $(describe) -> $DB"
    say "  stats: $STATSLOG$( [ $PCAP = 1 ] && echo "  pcap: $base.pcap")"
}

stop_pipeline() {
    if [ -n "$BIN_PID" ]; then
        kill -TERM "$BIN_PID" 2>/dev/null
        wait_pid "$BIN_PID" 5 || { kill -KILL "$BIN_PID" 2>/dev/null; wait_pid "$BIN_PID" 2; }
    fi
    if [ -n "$SINK_PID" ]; then
        # it commits what it has once the sniffer's output ends
        wait_pid "$SINK_PID" 10 || { kill -TERM "$SINK_PID" 2>/dev/null; wait_pid "$SINK_PID" 3 ||
            { kill -KILL "$SINK_PID" 2>/dev/null; wait_pid "$SINK_PID" 2; }; }
    fi
    BIN_PID='' SINK_PID='' RUN_CONFIG=''
}

cleanup() {
    trap - INT TERM HUP EXIT
    [ -n "$SLEEP_PID" ] && kill "$SLEEP_PID" 2>/dev/null
    if [ -n "$BIN_PID$SINK_PID" ]; then
        say "stopping"
        stop_pipeline
    fi
    if [ -n "$WEB_PID" ]; then
        kill -TERM "$WEB_PID" 2>/dev/null
        wait_pid "$WEB_PID" 3 || kill -KILL "$WEB_PID" 2>/dev/null
    fi
    rm -rf "$RUNDIR"
}
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 129' HUP
trap cleanup EXIT

# ---- start -----------------------------------------------------------------------------------

read_shm
if [ "$SHM_ALIVE" != 1 ]; then
    die "$(shm_problem)"
fi
read_receiver
rc=$?
[ $rc = 4 ] && die "$WHY"
if [ $CONFIGURE = 1 ]; then
    configure
    [ $DRY = 1 ] || read_receiver
fi
cat "$RUNDIR/check.err" >&2
if [ "$USABLE" != 1 ]; then
    die "the receiver is not set up for BLE: $WHY
  recommended: band 0, 160 Msps, LO 2441 MHz (all 40 channels within +-39 MHz, flat)
  set it in the spectrum page (Band 0, Sample rate 160 Msps, Apply; LO 2441 MHz) or run ./run.sh --configure$( [ $FORCE = 0 ] && echo "
  --force runs anyway when only the band edges do not fit")"
fi
if [ "${SHM_RATE:-0}" != 0 ] && [ "$SHM_RATE" != "$RATE" ]; then
    warn "the stream header says ${SHM_RATE} samples/s but the receiver reports $RATE: using $RATE (passed as --rate)"
fi
say "receiver: $(describe), stream service pid $SHM_PID"

mkdir -p "$LOGS" || die "cannot create $LOGS"
if [ $DRY = 1 ]; then
    sniffer_args "$LOGS/ble-TIME"
    say "dry run, would run:"
    [ -z "${W1700K_BLE_BIN:-}" ] && [ $BUILD = 1 ] && say "  make -C $HERE build/w1700k-ble"
    say "  $BIN ${ARGS[*]} | $PY $HERE/sink/w1700k_ble_sink.py ${SINK_ARGS[*]}"
    [ $WEB = 1 ] && say "  $PY $HERE/sink/ble_web.py --db $DB --host $WEB_HOST --port $WEB_PORT"
    exit 0
fi

if [ -z "${W1700K_BLE_BIN:-}" ] && [ $BUILD = 1 ]; then
    say "building (make build/w1700k-ble)"
    if ! make -s -C "$HERE" build/w1700k-ble >&2; then
        [ -x "$BIN" ] || die "the build failed and there is no $BIN"
        warn "the build failed: running the existing $BIN"
    fi
fi
[ -x "$BIN" ] || die "no sniffer at $BIN: run make"

if [ $WEB = 1 ]; then
    "$PY" "$HERE/sink/ble_web.py" --db "$DB" --host "$WEB_HOST" --port "$WEB_PORT" >>"$LOGS/web.log" 2>&1 &
    WEB_PID=$!
    sleep 0.5
    kill -0 "$WEB_PID" 2>/dev/null || { WEB_PID=''; die "the web UI did not start: $(tail -n 3 "$LOGS/web.log")"; }
    say "web UI: http://$WEB_HOST:$WEB_PORT/"
fi

start_pipeline
say "Ctrl-C stops everything"

# ---- watch -----------------------------------------------------------------------------------

FAILS=0 NEXT_TRY=0 LAST_NOTE=''
note() {    # say something once per change of state
    [ "$1" = "$LAST_NOTE" ] && return
    LAST_NOTE=$1
    say "$1"
}
while true; do
    sleep "$POLL" &
    SLEEP_PID=$!
    wait "$SLEEP_PID" 2>/dev/null
    SLEEP_PID=''
    now=$(date +%s)

    if [ -n "$BIN_PID" ] && ! kill -0 "$BIN_PID" 2>/dev/null; then
        wait "$BIN_PID" 2>/dev/null
        status=$?
        ran=$(( now - STARTED_AT ))
        warn "w1700k-ble exited (status $status) after ${ran} s"
        grep -v '^STATS ' "$STATSLOG" 2>/dev/null | tail -n 5 >&2
        stop_pipeline
        [ $WATCH = 1 ] || exit 1
        if [ $ran -lt 30 ]; then FAILS=$(( FAILS + 1 )); else FAILS=1; fi
        [ $FAILS -ge 5 ] && die "w1700k-ble keeps exiting; giving up (logs in $LOGS)"
        NEXT_TRY=$(( now + 5 * FAILS ))
    elif [ -n "$SINK_PID" ] && ! kill -0 "$SINK_PID" 2>/dev/null; then
        warn "the sink exited: restarting the pipeline"
        stop_pipeline
        [ $WATCH = 1 ] || exit 1
    fi
    if [ -n "$WEB_PID" ] && ! kill -0 "$WEB_PID" 2>/dev/null; then
        warn "the web UI exited: $(tail -n 2 "$LOGS/web.log")"
        WEB_PID=''
    fi

    read_shm
    if [ "$SHM_ALIVE" != 1 ]; then
        note "waiting: $(shm_problem)"
        continue
    fi
    if [ -n "$BIN_PID" ] && [ -n "$RUN_SHM_PID" ] && [ "$SHM_PID" != "$RUN_SHM_PID" ]; then
        say "w1700k-stream restarted (pid $RUN_SHM_PID -> $SHM_PID): restarting the sniffer"
        stop_pipeline
        [ $WATCH = 1 ] || exit 0
    fi
    read_receiver
    rc=$?
    if [ $rc = 4 ]; then
        note "warning: $WHY (keeping the sniffer as it is)"
        continue
    fi
    if [ -n "$BIN_PID" ]; then
        if [ "$USABLE" = 1 ] && [ "$BAND $LO_HZ $RATE" = "$RUN_CONFIG" ]; then
            LAST_NOTE=''
            continue
        fi
        if [ "$USABLE" = 1 ]; then
            say "receiver changed: $(describe): restarting the sniffer"
        else
            say "receiver changed: $WHY: stopping the sniffer"
        fi
        cat "$RUNDIR/check.err" >&2
        stop_pipeline
        [ $WATCH = 1 ] || exit 0
    fi
    if [ "$USABLE" != 1 ]; then
        note "waiting for a BLE setup: $WHY"
        continue
    fi
    [ "$now" -ge "$NEXT_TRY" ] || continue
    LAST_NOTE=''
    start_pipeline
done
