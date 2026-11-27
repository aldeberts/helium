#!/usr/bin/env bash
# Runs the aggregator, decryptor, and client on this machine over localhost,
# in simulated mode, for a list of configs.
#
#   run_local.sh <workdir> <config.json> [<config.json> ...]
#
# The servers are started from the first config, so the configs must share a
# number of clients and a threshold. Their file names must be distinct.
#
# Build first with `cargo build --release`. Logs and databases go to <workdir>.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <workdir> <config.json> [<config.json> ...]" >&2
  exit 1
fi

WORK="$1"
shift
BIN="$(cd "$(dirname "$0")/../.." && pwd)/target/release"
CLIENT_DB="$WORK/client.db"
export RUST_LOG=info

mkdir -p "$WORK/configs"
rm -rf "$WORK"/*.log "$WORK"/server.db* "$CLIENT_DB"

# Point each config at localhost and at a database inside the work directory
CONFIGS=()
for f in "$@"; do
  out="$WORK/configs/$(basename "$f")"
  jq --indent 4 --arg db "$WORK/server.db" '
    def port(x): (x | split(":") | .[1]);

    .aggregator_addr = ("127.0.0.1:" + port(.aggregator_addr)) |
    .decryptor_addr  = ("127.0.0.1:" + port(.decryptor_addr)) |
    .db_path = $db
  ' "$f" >"$out"
  CONFIGS+=("$out")
done

# wait_for_log <pattern> <file> <timeout in seconds>
wait_for_log() {
  for _ in $(seq 1 "$3"); do
    grep -q "$1" "$2" 2>/dev/null && return 0
    if ! kill -0 "$AGGREGATOR_PID" 2>/dev/null; then
      echo "The aggregator exited while waiting for '$1' in $2" >&2
      return 1
    fi
    sleep 1
  done
  echo "Timed out waiting for '$1' in $2" >&2
  return 1
}

# The logs are appended to, so that the markers written below survive.
"$BIN/exp_aggregator" "${CONFIGS[0]}" >>"$WORK/aggregator.log" 2>&1 &
AGGREGATOR_PID=$!
trap 'kill $AGGREGATOR_PID ${DECRYPTOR_PID:-} 2>/dev/null || true' EXIT
wait_for_log "Aggregator listening" "$WORK/aggregator.log" 60

"$BIN/exp_decryptor" "${CONFIGS[0]}" >>"$WORK/decryptor.log" 2>&1 &
DECRYPTOR_PID=$!
wait_for_log "Decryptor listening" "$WORK/decryptor.log" 60

client() {
  "$BIN/exp_client" "$@" --client-db "$CLIENT_DB" >>"$WORK/client.log" 2>&1
}

# Run setup once. The aggregator finishes it in the background (it encrypts
# every client's key); waiting here keeps that out of the first round's numbers.
client "${CONFIGS[0]}" --mode sim-setup
wait_for_log "Setup complete" "$WORK/aggregator.log" 86400

for f in "${CONFIGS[@]}"; do
  echo "=== Config: $(basename "$f") ===" | tee -a "$WORK"/{client,aggregator,decryptor}.log
  client "$f" --mode sim-generate
  client "$f" --mode aggregate
done
