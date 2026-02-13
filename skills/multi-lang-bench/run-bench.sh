#!/usr/bin/env bash
###############################################################################
# run-bench.sh — Multi-language benchmark across pi, codex, claude, gemini
#
# Usage: ./run-bench.sh [N]
#   N = total number of tests (default: 12)
#
# Execution model:
#   - Tests are split into batches of BATCH_SIZE=3
#   - Wave 1 (parallel): pi + codex      (base timeout)
#   - Wave 2 (parallel): claude + gemini  (5× timeout)
#   - pi & claude never run simultaneously (same underlying model)
#
# Output: results/multilang-bench/<run-id>/summary.md
###############################################################################
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
BENCH_DIR="/home/node/git/bench"
SCRIPTS_DIR="$BENCH_DIR/scripts/languages"

# --- Parameters ---
TOTAL_N="${1:-12}"
BATCH_SIZE=3
BASE_TIMEOUT=600
SLOW_TIMEOUT=$((BASE_TIMEOUT * 5))   # 3000s for claude+gemini wave
VALIDATE_FLAG="--validate"

RUN_ID="$(date +%Y%m%d-%H%M%S)-multilang-bench"
RESULTS_BASE="$BENCH_DIR/results/multilang-bench/$RUN_ID"
LOG_DIR="$RESULTS_BASE/logs"
mkdir -p "$RESULTS_BASE" "$LOG_DIR"

AGENTS=(pi codex claude gemini)
TEST_LIST="$BENCH_DIR/tests/multilang/round-robin-by-language.md"
DATASET_CACHE="$BENCH_DIR/cache/multilang"

###############################################################################
# Step 0 — Ensure dataset & test lists exist
###############################################################################
echo "============================================================"
echo " Multi-Language Benchmark — $TOTAL_N tests, batches of $BATCH_SIZE"
echo " Run ID: $RUN_ID"
echo " Base timeout: ${BASE_TIMEOUT}s | Slow wave: ${SLOW_TIMEOUT}s"
echo "============================================================"

bash "$SCRIPTS_DIR/multilang-cache.sh" 2>&1 | tail -3

if [[ ! -f "$TEST_LIST" ]]; then
  echo "[bench] Building test lists..."
  bash "$SCRIPTS_DIR/multilang-build-test-lists.sh" 2>&1 | tail -3
fi

###############################################################################
# Step 1 — Select N instance IDs
###############################################################################
echo "[bench] Selecting $TOTAL_N instance IDs from round-robin list..."

SELECTED_IDS=()
while IFS= read -r line; do
  line="$(echo "$line" | xargs)"
  [[ -z "$line" || "$line" == \#* ]] && continue
  SELECTED_IDS+=("$line")
  [[ ${#SELECTED_IDS[@]} -ge $TOTAL_N ]] && break
done < "$TEST_LIST"

ACTUAL_N=${#SELECTED_IDS[@]}
echo "[bench] Selected $ACTUAL_N instance IDs"

if [[ $ACTUAL_N -eq 0 ]]; then
  echo "ERROR: No instance IDs selected" >&2; exit 1
fi

###############################################################################
# Step 2 — Split into batches of BATCH_SIZE
###############################################################################
declare -a BATCHES=()
batch=""
count=0
for id in "${SELECTED_IDS[@]}"; do
  [[ -n "$batch" ]] && batch+=","
  batch+="$id"
  count=$((count + 1))
  if [[ $count -ge $BATCH_SIZE ]]; then
    BATCHES+=("$batch")
    batch=""
    count=0
  fi
done
[[ -n "$batch" ]] && BATCHES+=("$batch")

NUM_BATCHES=${#BATCHES[@]}
echo "[bench] Split into $NUM_BATCHES batches of up to $BATCH_SIZE"

###############################################################################
# Helper — run one agent on one batch
###############################################################################
run_agent_batch() {
  local agent="$1" batch_ids="$2" batch_idx="$3" timeout="$4"
  local agent_results="$RESULTS_BASE/$agent"
  local log="$LOG_DIR/${agent}-batch${batch_idx}.log"
  mkdir -p "$agent_results"

  echo "  [wave] Starting $agent (batch $batch_idx, timeout=${timeout}s)..."

  bash "$SCRIPTS_DIR/multilang-run.sh" \
    --agent "$agent" \
    --instance-ids "$batch_ids" \
    --timeout "$timeout" \
    --results-dir "$agent_results" \
    $VALIDATE_FLAG \
    > "$log" 2>&1 || true

  echo "  [wave] $agent batch $batch_idx done — log: $log"
}

###############################################################################
# Step 3 — Run batches: Wave1 (pi+codex) then Wave2 (claude+gemini)
###############################################################################
for bi in "${!BATCHES[@]}"; do
  batch_num=$((bi + 1))
  batch_ids="${BATCHES[$bi]}"
  echo ""
  echo "========== Batch $batch_num / $NUM_BATCHES =========="
  echo "  IDs: $batch_ids"

  # --- Wave 1: pi + codex (parallel, base timeout) ---
  echo "  --- Wave 1: pi + codex (parallel) ---"
  run_agent_batch "pi"    "$batch_ids" "$batch_num" "$BASE_TIMEOUT" &
  pid_pi=$!
  run_agent_batch "codex" "$batch_ids" "$batch_num" "$BASE_TIMEOUT" &
  pid_codex=$!

  wait $pid_pi    || echo "  [warn] pi batch $batch_num had errors"
  wait $pid_codex || echo "  [warn] codex batch $batch_num had errors"

  # --- Wave 2: claude + gemini (parallel, 5× timeout) ---
  echo "  --- Wave 2: claude + gemini (parallel, ${SLOW_TIMEOUT}s timeout) ---"
  run_agent_batch "claude" "$batch_ids" "$batch_num" "$SLOW_TIMEOUT" &
  pid_claude=$!
  run_agent_batch "gemini" "$batch_ids" "$batch_num" "$SLOW_TIMEOUT" &
  pid_gemini=$!

  wait $pid_claude || echo "  [warn] claude batch $batch_num had errors"
  wait $pid_gemini || echo "  [warn] gemini batch $batch_num had errors"

  echo "  Batch $batch_num complete."
done

echo ""
echo "[bench] All batches complete. Generating summary..."

###############################################################################
# Step 4 — Collect results and generate summary tables
###############################################################################
python3 "$SKILL_DIR/generate-summary.py" "$RESULTS_BASE" "${AGENTS[@]}"

echo ""
echo "[bench] Summary written to: $RESULTS_BASE/summary.md"
echo "[bench] JSON data:          $RESULTS_BASE/summary.json"
cat "$RESULTS_BASE/summary.md"
