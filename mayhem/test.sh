#!/usr/bin/env bash
#
# mayhem/test.sh — run the CleverCSV unittest suite via the compiled ELF runner and emit CTRF.
set -uo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
SRC="${SRC:-/mayhem}"
cd "$SRC"

emit_ctrf() {
    local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
    local tests=$(( passed + failed + skipped + pending + other ))
    cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
    printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
        "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
    [ "$failed" -eq 0 ]
}

RUNNER="$SRC/run_tests"
if [ ! -x "$RUNNER" ]; then
    echo "test.sh: $RUNNER missing/not executable — mayhem/build.sh must build it first" >&2
    emit_ctrf "clevercsv-unittest" 0 1 0
    exit 1
fi

echo ">> running CleverCSV test suite via $RUNNER"
raw=$("$RUNNER" 2>&1) || true

echo "$raw"

total=$(echo "$raw" | grep -oE 'Ran [0-9]+ test' | grep -oE '[0-9]+' | tail -1 || echo 0)
total="${total:-0}"

if echo "$raw" | grep -qE '^OK$'; then
    passed="$total"
    failed=0
elif echo "$raw" | grep -qE '^FAILED'; then
    fails=$(echo "$raw" | grep -oE 'failures=[0-9]+' | grep -oE '[0-9]+' | head -1 || echo 0)
    errs=$(echo  "$raw" | grep -oE 'errors=[0-9]+'   | grep -oE '[0-9]+' | head -1 || echo 0)
    failed=$(( ${fails:-0} + ${errs:-0} ))
    passed=$(( total - failed ))
else
    failed=1
    passed=0
fi

emit_ctrf "clevercsv-unittest" "$passed" "$failed"
