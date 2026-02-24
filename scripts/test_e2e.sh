#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  scripts/test_e2e.sh [options]

Options:
  --run-dir <path>                   run/output directory (default: ./_ebpf_run)
  --workspace-host <path>            host workspace path bind-mounted to /workspace
  --workspace-id <id>                workspace id (default: e2e-workspace)
  --container-name <name>            reusable container name (default: attested-e2e)
  --policy <path>                    use explicit policy file (skip auto-generated e2e policy)
  --forbidden-exec-sha256s <csv>     comma-separated forbidden exec hashes for auto-generated policy
  --expect-fail                      treat attest/verify failure as expected
  --tamper-raw-log-after-attest      tamper local raw audit log after attest and expect verify to fail with AUDIT_LOG_INTEGRITY_MISMATCH
  -h, --help                         show this help
USAGE
}

RUN_DIR=""
WORK_DIR=""
WORKSPACE_ID="e2e-workspace"
CONTAINER_NAME="attested-e2e"
POLICY_PATH=""
FORBID_LIST=""
EXPECT_FAIL=0
TAMPER_RAW_LOG_AFTER_ATTEST=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-dir)
      RUN_DIR="${2:-}"
      shift 2
      ;;
    --workspace-host)
      WORK_DIR="${2:-}"
      shift 2
      ;;
    --workspace-id)
      WORKSPACE_ID="${2:-}"
      shift 2
      ;;
    --container-name)
      CONTAINER_NAME="${2:-}"
      shift 2
      ;;
    --policy)
      POLICY_PATH="${2:-}"
      shift 2
      ;;
    --forbidden-exec-sha256s)
      FORBID_LIST="${2:-}"
      shift 2
      ;;
    --expect-fail)
      EXPECT_FAIL=1
      shift
      ;;
    --tamper-raw-log-after-attest)
      TAMPER_RAW_LOG_AFTER_ATTEST=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$TAMPER_RAW_LOG_AFTER_ATTEST" == "1" ]]; then
  EXPECT_FAIL=1
fi

for cmd in go docker openssl git python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "$cmd not found"
    exit 1
  fi
done

if [[ -z "$RUN_DIR" ]]; then
  RUN_DIR="$ROOT_DIR/_ebpf_run"
fi
STATE_DIR="$RUN_DIR/state"
if [[ -z "$WORK_DIR" ]]; then
  WORK_DIR="$RUN_DIR/workspace"
fi
KEYS_DIR="$RUN_DIR/keys"
ATTEST_DIR="$RUN_DIR/attestations"
mkdir -p "$STATE_DIR" "$WORK_DIR" "$KEYS_DIR" "$ATTEST_DIR"

PRIV="$KEYS_DIR/attestation_priv.pem"
PUB="$KEYS_DIR/attestation_pub.pem"
WORKSPACE_META="$STATE_DIR/workspaces/${WORKSPACE_ID}.json"
COLLECT_PIDS=()
SESSIONS=()
CONTAINER_ID=""
WORKSPACE_INIT_DONE=0

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo
    echo "[cleanup] script failed (rc=$rc); attempting workspace cleanup" >&2
    if [[ $WORKSPACE_INIT_DONE -eq 1 ]]; then
      go run ./cmd/attested workspace rm --state-dir "$STATE_DIR" --workspace-id "$WORKSPACE_ID" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT

run_collector_for_session() {
  local session_id="$1"
  local log_path="$2"

  sudo go run ./cmd/attested collect \
    --session "$session_id" \
    --state-dir "$STATE_DIR" \
    --until-stop \
    >"$log_path" 2>&1 &
  local collect_pid=$!
  COLLECT_PIDS+=("$collect_pid")

  local pid_file="$STATE_DIR/sessions/$session_id/collector.pid"
  for _ in $(seq 1 40); do
    if [[ -f "$pid_file" ]]; then
      break
    fi
    if ! kill -0 "$collect_pid" 2>/dev/null; then
      echo "error: collector exited before ready (session=$session_id)" >&2
      echo "--- collector log ($session_id) ---" >&2
      cat "$log_path" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  if [[ ! -f "$pid_file" ]]; then
    echo "error: collector did not become ready (session=$session_id)" >&2
    echo "--- collector log ($session_id) ---" >&2
    cat "$log_path" >&2 || true
    return 1
  fi
}

finalize_and_attest_session() {
  local session_id="$1"
  local session_label="$2"
  local collector_log="$3"

  echo "[$session_label] stop session + finalize collector (keep container)"
  set +e
  go run ./cmd/attested stop \
    --session "$session_id" \
    --state-dir "$STATE_DIR" \
    --collector-wait 60s \
    --keep-container
  local stop_rc=$?
  set -e
  if [[ "$stop_rc" -ne 0 ]]; then
    echo "error: stop failed (rc=$stop_rc, session=$session_id)" >&2
    echo "--- collector log ($session_id) ---" >&2
    cat "$collector_log" >&2 || true
    echo "--- session dir ($session_id) ---" >&2
    ls -la "$STATE_DIR/sessions/$session_id" >&2 || true
    return "$stop_rc"
  fi

  local summary_path="$STATE_DIR/sessions/$session_id/audit_summary.json"
  local binding_path="$STATE_DIR/sessions/$session_id/commit_binding.json"

  if [[ -z "$POLICY_PATH" ]]; then
    POLICY_PATH="$RUN_DIR/policy.e2e.yaml"
    echo "[$session_label] build e2e policy (blocklist-style writers)"
    python3 - "$summary_path" "$POLICY_PATH" "$FORBID_LIST" <<'PY'
import json, sys
summary_path, policy_path, forbid_csv = sys.argv[1], sys.argv[2], sys.argv[3]
with open(summary_path, 'r', encoding='utf-8') as f:
    _ = json.load(f)
forbidden = sorted({x.strip() for x in forbid_csv.split(',') if x.strip()})
with open(policy_path, 'w', encoding='utf-8') as f:
    f.write('policy_id: "poc-e2e"\n')
    f.write('policy_version: "1.0.0"\n\n')
    if not forbidden:
        f.write('forbidden_exec: []\n\n')
    else:
        f.write('forbidden_exec:\n')
        for h in forbidden:
            f.write(f'  - sha256: "{h}"\n')
            f.write('    comment: "e2e forbidden"\n')
        f.write('\n')
    f.write('forbidden_writers: []\n\n')
    f.write('exceptions: []\n')
PY
  fi

  echo "[$session_label] create git commit binding in dummy repo"
  if [[ ! -d "$WORK_DIR/.git" ]]; then
    git -C "$WORK_DIR" init -b main >/dev/null 2>&1 || git -C "$WORK_DIR" init >/dev/null 2>&1
  fi
  git -C "$WORK_DIR" config user.name "attested-e2e"
  git -C "$WORK_DIR" config user.email "attested-e2e@example.local"
  git -C "$WORK_DIR" add -A

  COMMIT_JSON=$(go run ./cmd/attested commit \
    --session "$session_id" \
    --state-dir "$STATE_DIR" \
    --repo-path "$WORK_DIR" \
    --message "e2e session $session_label ($session_id)" \
    --json)
  local commit_sha
  commit_sha=$(echo "$COMMIT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['commit_sha'])")
  echo "  linked_commit=$commit_sha"

  local out_dir="$ATTEST_DIR/$commit_sha"
  mkdir -p "$out_dir"

  echo "[$session_label] attest"
  set +e
  go run ./cmd/attested attest \
    --session "$session_id" \
    --state-dir "$STATE_DIR" \
    --repo local/test \
    --policy "$POLICY_PATH" \
    --out "$out_dir" \
    --signing-key "$PRIV" \
    --use-binding \
    --key-id poc-key-1 \
    --issuer-name session-attested
  local attest_rc=$?
  set -e

  if [[ "$EXPECT_FAIL" == "1" ]]; then
    if [[ "$attest_rc" -eq 0 ]]; then
      echo "error: expected attest to fail, but it succeeded ($session_label)" >&2
      return 1
    fi
    echo "attest failed as expected (rc=$attest_rc)"
  else
    if [[ "$attest_rc" -ne 0 ]]; then
      echo "error: attest failed unexpectedly (rc=$attest_rc, $session_label)" >&2
      return "$attest_rc"
    fi
  fi

  echo "[$session_label] verify"
  if [[ "$TAMPER_RAW_LOG_AFTER_ATTEST" == "1" ]]; then
    echo "[$session_label] tamper local raw audit log before verify (expected integrity mismatch)"
    python3 - "$STATE_DIR/sessions/$session_id/audit_workspace_write.jsonl" <<'PY'
import json, sys
p = sys.argv[1]
with open(p, 'r', encoding='utf-8') as f:
    lines = [ln.rstrip('\n') for ln in f if ln.strip()]
if not lines:
    raise SystemExit("no audit_workspace_write.jsonl lines to tamper")
obj = json.loads(lines[0])
obj["comm"] = "tampered-e2e"
lines[0] = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
with open(p, 'w', encoding='utf-8') as f:
    for ln in lines:
        f.write(ln + "\n")
PY
  fi
  set +e
  go run ./cmd/attested verify \
    --attestation "$out_dir/attestation.json" \
    --signature "$out_dir/attestation.sig" \
    --public-key "$out_dir/attestation.pub" \
    --policy "$POLICY_PATH" \
    --binding "$binding_path"
  local verify_rc=$?
  set -e

  if [[ "$EXPECT_FAIL" == "1" ]]; then
    if [[ "$verify_rc" -eq 0 ]]; then
      echo "error: expected verify to fail, but it succeeded ($session_label)" >&2
      return 1
    fi
    echo "verify failed as expected (rc=$verify_rc)"
    if [[ "$TAMPER_RAW_LOG_AFTER_ATTEST" == "1" ]]; then
      local verify_json
      verify_json=$(go run ./cmd/attested verify \
        --attestation "$out_dir/attestation.json" \
        --signature "$out_dir/attestation.sig" \
        --public-key "$out_dir/attestation.pub" \
        --policy "$POLICY_PATH" \
        --binding "$binding_path" \
        --json || true)
      echo "[$session_label] verify(json after tamper): $verify_json"
      if [[ "$verify_json" != *"AUDIT_LOG_INTEGRITY_MISMATCH"* ]]; then
        echo "error: expected AUDIT_LOG_INTEGRITY_MISMATCH after tamper ($session_label)" >&2
        return 1
      fi
    fi
  else
    if [[ "$verify_rc" -ne 0 ]]; then
      echo "error: verify failed unexpectedly (rc=$verify_rc, $session_label)" >&2
      return "$verify_rc"
    fi
  fi

  echo "[$session_label] attestation: $out_dir/attestation.json"
}

run_session() {
  local index="$1"
  local session_label="session-${index}"
  local start_json session_id container_id collector_log

  echo "[$session_label] start session (reuse container)"
  start_json=$(go run ./cmd/attested start \
    --image ubuntu:24.04 \
    --name "$CONTAINER_NAME" \
    --reuse-container \
    --state-dir "$STATE_DIR" \
    --workspace-host "$WORK_DIR" \
    --json)

  session_id=$(echo "$start_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
  container_id=$(echo "$start_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['container_id'])")
  CONTAINER_ID="$container_id"
  SESSIONS+=("$session_id")
  echo "  session_id=$session_id"
  echo "  container_id=$container_id"

  collector_log="$RUN_DIR/collector-${session_id}.log"
  echo "[$session_label] start collector daemon (requires sudo)"
  run_collector_for_session "$session_id" "$collector_log"

  echo "[$session_label] run commands inside container"
  if [[ "$index" == "1" ]]; then
    docker exec "$container_id" bash -lc "mkdir -p /workspace && date -u +%s%N > /workspace/a.txt"
    docker exec "$container_id" bash -lc "echo session1 >> /workspace/shared.txt"
  else
    docker exec "$container_id" bash -lc "date -u +%s%N > /workspace/b.txt"
    docker exec "$container_id" bash -lc "echo session2 >> /workspace/shared.txt"
  fi
  docker exec "$container_id" bash -lc "ls /workspace"
  docker exec "$container_id" bash -lc "uname -a"
  docker exec "$container_id" bash -lc "id"

  finalize_and_attest_session "$session_id" "$session_label" "$collector_log"
}

echo "[1] build / generate BPF"
go generate ./internal/collector/ebpf
go build ./...

echo "[2] generate test key"
openssl genpkey -algorithm Ed25519 -out "$PRIV" >/dev/null 2>&1
openssl pkey -in "$PRIV" -pubout -out "$PUB" >/dev/null 2>&1
chmod 600 "$PRIV"

echo "[3] workspace init (container create only)"
go run ./cmd/attested workspace init \
  --workspace-id "$WORKSPACE_ID" \
  --workspace-host "$WORK_DIR" \
  --name "$CONTAINER_NAME" \
  --image ubuntu:24.04 \
  --pull \
  --state-dir "$STATE_DIR"
WORKSPACE_INIT_DONE=1

echo "[4] session cycle #1"
run_session 1

echo "[5] session cycle #2"
run_session 2

echo "[6] workspace rm (container delete)"
go run ./cmd/attested workspace rm \
  --workspace-id "$WORKSPACE_ID" \
  --state-dir "$STATE_DIR"
WORKSPACE_INIT_DONE=0

echo

echo "=============================="
echo "E2E TEST COMPLETED (2 sessions / 1 workspace)"
echo "workspace_id: $WORKSPACE_ID"
echo "container:    $CONTAINER_ID"
echo "sessions:     ${SESSIONS[*]}"
echo "state dir:    $STATE_DIR"
if [[ -n "$POLICY_PATH" ]]; then
  echo "policy:       $POLICY_PATH"
fi
if [[ "$EXPECT_FAIL" == "1" ]]; then
  echo "mode:         negative (expected fail)"
fi
echo "=============================="
