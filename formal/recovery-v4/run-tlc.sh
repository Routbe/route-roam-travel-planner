#!/usr/bin/env bash
# Model-checks Recovery v4 with TLC.
#   1. The three main models must pass: every invariant, action property and
#      liveness property holds, and there is no deadlock.
#   2. Every mutant (one protection switched off) must FAIL on exactly the
#      property named in its .cfg header, which proves that property guards it.
#   3. Every reachability witness W_* must be reached, which proves the
#      interesting situations (upgrade, downgrade, torn card, replay, ...) are
#      actually explored and the passes in step 1 are not vacuous.
# Usage: TLA_JAR=/path/tla2tools.jar [JAVA=java] [TLC_WORKERS=auto] ./run-tlc.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAVA="${JAVA:-java}"
TLA_JAR="${TLA_JAR:?set TLA_JAR to the pinned tla2tools.jar}"
WORKERS="${TLC_WORKERS:-auto}"
OUT="${TLC_OUT:-${RUNNER_TEMP:-/tmp}/tlc-recovery-v4}"
SPEC="$HERE/RecoveryV4.tla"
rm -rf "$OUT" && mkdir -p "$OUT"
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
fail=0

tlc() { # name cfg
  local name="$1" cfg="$2" code=0
  "$JAVA" -XX:+UseParallelGC -Xss16m -cp "$TLA_JAR" tlc2.TLC \
    -workers "$WORKERS" -cleanup -metadir "$OUT/states-$name" \
    -config "$cfg" "$SPEC" > "$OUT/$name.log" 2>&1 || code=$?
  echo "$code"
}

stats() { grep -E "^[0-9]+ states generated|depth of the complete" "$1" | tr '\n' ' ' | sed 's/  */ /g'; }

expect_pass() { # name cfg
  local code; code="$(tlc "$1" "$2")"
  if [ "$code" = 0 ] && grep -q "Model checking completed. No error has been found." "$OUT/$1.log"; then
    echo "PASS  $1: no violation, no deadlock. $(stats "$OUT/$1.log")" | tee -a "$SUMMARY"
  else
    echo "FAIL  $1: TLC exit $code (see $OUT/$1.log)" | tee -a "$SUMMARY"
    grep -E "violated|Error|deadlock" "$OUT/$1.log" | head -5 | tee -a "$SUMMARY" || true
    fail=1
  fi
}

expect_violation() { # name cfg property
  local code first; code="$(tlc "$1" "$2")"
  first="$(grep -m1 -E "is violated|were violated" "$OUT/$1.log" || true)"
  if [ "$code" != 0 ] && printf '%s' "$first" | grep -qw "$3"; then
    echo "PASS  $1: counterexample found as required -> $first" | tee -a "$SUMMARY"
  else
    echo "FAIL  $1: expected a violation of $3, got exit $code: ${first:-none} (see $OUT/$1.log)" | tee -a "$SUMMARY"
    fail=1
  fi
}

echo "== Main models (must hold)" | tee -a "$SUMMARY"
for cfg in RecoveryV4 RecoveryV4_live RecoveryV4_faults; do
  expect_pass "$cfg" "$HERE/$cfg.cfg"
done

echo "== Mutants (must break)" | tee -a "$SUMMARY"
for cfg in "$HERE"/mutants/*.cfg; do
  prop="$(sed -n 's/^\\\* run-tlc.sh requires TLC to report: //p' "$cfg")"
  expect_violation "mutant-$(basename "$cfg" .cfg)" "$cfg" "$prop"
done

echo "== Reachability witnesses (must be reached)" | tee -a "$SUMMARY"
# TLC resolves a .cfg only below the spec's own directory.
WDIR="$(mktemp -d "$HERE/.tlc-witness.XXXXXX")"
trap 'rm -rf "$WDIR"' EXIT
for w in $(grep -oE '^W_[A-Za-z0-9]+' "$SPEC"); do
  cfg="$WDIR/$w.cfg"
  sed -e '/^INVARIANTS/d' -e '/^PROPERTIES/d' "$HERE/RecoveryV4.cfg" > "$cfg"
  echo "INVARIANT $w" >> "$cfg"
  expect_violation "witness-$w" "$cfg" "$w"
done

echo | tee -a "$SUMMARY"
if [ "$fail" = 0 ]; then echo "ALL TLC CHECKS PASSED" | tee -a "$SUMMARY"; else echo "TLC CHECKS FAILED" | tee -a "$SUMMARY"; fi
exit "$fail"
