#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT_DIR/build"
CONFIG_DIR="$ROOT_DIR/config"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/stress_logs}"

CLIENTS=${CLIENTS:-50}
PARALLEL=${PARALLEL:-10}
SERVICE_ID=${SERVICE_ID:-fileserver}
SERVICE_PORT=${SERVICE_PORT:-9001}
AS_PORTS=${AS_PORTS:-8001,8002,8003}
TGS_PORTS=${TGS_PORTS:-8101,8102,8103}
USERNAME=${USERNAME:-alice}
PASSWORD=${PASSWORD:-alice123}

now_ms() {
  if command -v perl >/dev/null 2>&1; then
    LC_ALL=C perl -MTime::HiRes=time -e 'printf("%.0f\n", time()*1000)' 2>/dev/null
  else
    echo "$(( $(date +%s) * 1000 ))"
  fi
}

mkdir -p "$LOG_DIR"

IFS=',' read -r AS1_PORT AS2_PORT AS3_PORT <<<"$AS_PORTS"
IFS=',' read -r TGS1_PORT TGS2_PORT TGS3_PORT <<<"$TGS_PORTS"
if [[ -z "${AS1_PORT:-}" || -z "${AS2_PORT:-}" || -z "${AS3_PORT:-}" ]]; then
  echo "[stress] AS_PORTS must have exactly 3 comma-separated ports"
  exit 1
fi
if [[ -z "${TGS1_PORT:-}" || -z "${TGS2_PORT:-}" || -z "${TGS3_PORT:-}" ]]; then
  echo "[stress] TGS_PORTS must have exactly 3 comma-separated ports"
  exit 1
fi

cleanup() {
  if [[ -n "${PIDS:-}" ]]; then
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  fi
  wait 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -x "$BUILD_DIR/master_keygen" ]]; then
  echo "[stress] build artifacts missing; building..."
  cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
  cmake --build "$BUILD_DIR" -j4
fi

# fresh config and keys for consistency
"$BUILD_DIR/master_keygen" --regen >"$LOG_DIR/keygen.log" 2>&1

PIDS=""
"$BUILD_DIR/as_node" 1 "$AS1_PORT" >"$LOG_DIR/as1.log" 2>&1 & PIDS+="$! "
"$BUILD_DIR/as_node" 2 "$AS2_PORT" >"$LOG_DIR/as2.log" 2>&1 & PIDS+="$! "
"$BUILD_DIR/as_node" 3 "$AS3_PORT" >"$LOG_DIR/as3.log" 2>&1 & PIDS+="$! "
"$BUILD_DIR/tgs_node" 1 "$TGS1_PORT" >"$LOG_DIR/tgs1.log" 2>&1 & PIDS+="$! "
"$BUILD_DIR/tgs_node" 2 "$TGS2_PORT" >"$LOG_DIR/tgs2.log" 2>&1 & PIDS+="$! "
"$BUILD_DIR/tgs_node" 3 "$TGS3_PORT" >"$LOG_DIR/tgs3.log" 2>&1 & PIDS+="$! "
"$BUILD_DIR/service_server" "$SERVICE_ID" "$SERVICE_PORT" >"$LOG_DIR/service.log" 2>&1 & PIDS+="$! "

sleep 2

# Fail fast if ports are occupied or servers crash at startup.
for p in $PIDS; do
  if ! kill -0 "$p" 2>/dev/null; then
    echo "[stress] Server process $p exited during startup."
    echo "[stress] Check logs under $LOG_DIR"
    exit 1
  fi
done

STARTUP_RE='Failed to bind|Cannot bind|Cannot bind port|Failed to listen|Network init failed'
if command -v rg >/dev/null 2>&1; then
  BIND_CHECK_CMD='rg -n'
else
  BIND_CHECK_CMD='grep -nE'
fi

if $BIND_CHECK_CMD "$STARTUP_RE" \
  "$LOG_DIR/as1.log" "$LOG_DIR/as2.log" "$LOG_DIR/as3.log" \
  "$LOG_DIR/tgs1.log" "$LOG_DIR/tgs2.log" "$LOG_DIR/tgs3.log" "$LOG_DIR/service.log" >/dev/null 2>&1; then
  echo "[stress] Startup failure detected (likely port conflict)."
  $BIND_CHECK_CMD "$STARTUP_RE" \
    "$LOG_DIR/as1.log" "$LOG_DIR/as2.log" "$LOG_DIR/as3.log" \
    "$LOG_DIR/tgs1.log" "$LOG_DIR/tgs2.log" "$LOG_DIR/tgs3.log" "$LOG_DIR/service.log" || true
  exit 1
fi

SEQ_FILE="$LOG_DIR/seq.txt"
seq 1 "$CLIENTS" > "$SEQ_FILE"

METRICS_FILE="$LOG_DIR/metrics.csv"
LATENCY_FILE="$LOG_DIR/latency_ok_ms.txt"
SUMMARY_FILE="$LOG_DIR/metrics_summary.txt"

export BUILD_DIR SERVICE_ID SERVICE_PORT AS_PORTS TGS_PORTS USERNAME PASSWORD LOG_DIR METRICS_FILE

run_one() {
  local i="$1"
  local start_ms end_ms dur_ms
  local out="$LOG_DIR/client_${i}.log"
  local status="FAIL"
  start_ms=$(now_ms)
  if "$BUILD_DIR/client" "$USERNAME" "$PASSWORD" "$SERVICE_ID" \
    --as-ports "$AS_PORTS" --tgs-ports "$TGS_PORTS" --svc-port "$SERVICE_PORT" \
    >"$out" 2>&1; then
    :
  fi
  if grep -q "Authentication SUCCEEDED" "$out"; then
    status="OK"
  else
    echo "$i" >>"$LOG_DIR/failures.txt"
  fi
  end_ms=$(now_ms)
  dur_ms=$((end_ms - start_ms))
  printf "%s,%s,%s\n" "$i" "$status" "$dur_ms" >>"$METRICS_FILE"
}
export -f now_ms
export -f run_one

: >"$LOG_DIR/failures.txt"
echo "client_id,status,latency_ms" >"$METRICS_FILE"

# parallel client runs
RUN_START_MS=$(now_ms)
cat "$SEQ_FILE" | xargs -I{} -P "$PARALLEL" bash -c 'run_one "$@"' _ {}
RUN_END_MS=$(now_ms)
TOTAL_MS=$((RUN_END_MS - RUN_START_MS))

FAIL_COUNT=$(wc -l <"$LOG_DIR/failures.txt" | tr -d ' ')
SUCCESS_COUNT=$((CLIENTS - FAIL_COUNT))

awk -F, 'NR>1 && $2=="OK" {print $3}' "$METRICS_FILE" | sort -n >"$LATENCY_FILE"
OK_COUNT=$(wc -l <"$LATENCY_FILE" | tr -d ' ')

pick_percentile() {
  local pct="$1"
  local n="$2"
  local file="$3"
  if [[ "$n" -le 0 ]]; then
    echo "n/a"
    return
  fi
  local idx=$(( (pct * n + 99) / 100 ))
  if [[ "$idx" -lt 1 ]]; then idx=1; fi
  if [[ "$idx" -gt "$n" ]]; then idx="$n"; fi
  sed -n "${idx}p" "$file"
}

if [[ "$OK_COUNT" -gt 0 ]]; then
  P50_MS=$(pick_percentile 50 "$OK_COUNT" "$LATENCY_FILE")
  P95_MS=$(pick_percentile 95 "$OK_COUNT" "$LATENCY_FILE")
  P99_MS=$(pick_percentile 99 "$OK_COUNT" "$LATENCY_FILE")
  MEAN_MS=$(awk '{s+=$1} END {printf "%.2f", (NR ? s/NR : 0)}' "$LATENCY_FILE")
else
  P50_MS="n/a"
  P95_MS="n/a"
  P99_MS="n/a"
  MEAN_MS="n/a"
fi

THROUGHPUT=$(awk -v ok="$SUCCESS_COUNT" -v t="$TOTAL_MS" 'BEGIN {if (t > 0) printf "%.2f", (ok*1000)/t; else print "0.00"}')
SUCCESS_RATE=$(awk -v ok="$SUCCESS_COUNT" -v c="$CLIENTS" 'BEGIN {if (c > 0) printf "%.2f", (ok*100)/c; else print "0.00"}')

{
  echo "clients=$CLIENTS"
  echo "parallel=$PARALLEL"
  echo "success=$SUCCESS_COUNT"
  echo "fail=$FAIL_COUNT"
  echo "success_rate_pct=$SUCCESS_RATE"
  echo "total_runtime_ms=$TOTAL_MS"
  echo "throughput_auth_per_sec=$THROUGHPUT"
  echo "latency_mean_ms=$MEAN_MS"
  echo "latency_p50_ms=$P50_MS"
  echo "latency_p95_ms=$P95_MS"
  echo "latency_p99_ms=$P99_MS"
} >"$SUMMARY_FILE"

if [[ "$FAIL_COUNT" -eq 0 ]]; then
  echo "[stress] OK: $CLIENTS clients, $PARALLEL parallel, no failures."
else
  echo "[stress] FAIL: $FAIL_COUNT / $CLIENTS clients failed. See $LOG_DIR/failures.txt"
  exit 1
fi

echo "[stress] Metrics summary: $SUMMARY_FILE"
cat "$SUMMARY_FILE"
