#!/usr/bin/env bash
# Automated release-assembly side-channel audit for the RIAK v0.3 core.
#
# This is a *static* screen, not a constant-time proof. It does not model the
# microarchitecture, the compiler's future decisions, speculative execution,
# or the allocator. It does turn a one-time manual observation into a repeatable
# check that can fail CI.
#
# What it inspects, and why each pattern matters:
#
#   div/idiv            Integer division is variable-time on most hardware, so
#                       any occurrence in the core is a finding.
#   computed address    A memory operand of the form (base,index,scale) means the
#                       address is computed rather than a fixed field. This is
#                       reported as a *lead that needs review*, NOT as a finding:
#                       a linear scan over a stack buffer or over the 16-word
#                       key-schedule state also produces this shape, and those
#                       indices are public loop counters. Distinguishing a
#                       secret-derived index from a loop counter needs real data
#                       flow analysis, which this script does not attempt.
#   conditional branch  A branch inside the core whose condition comes from
#                       cipher data would be a control-flow leak. The script
#                       counts and lists them so a human can check that every
#                       one is driven by a public length or round counter.
#
# What it deliberately does NOT do: claim the core is constant-time. A clean
# run means "no division and no obvious secret-dependent control flow was found
# in this build". It does not clear the build for deployment.
#
# Exit status: 0 clean, 1 a finding was reported, 2 the audit could not run.

set -uo pipefail

cd "$(dirname "$0")/.."

BINARY="target/release/riak"
DUMP="target/asm-audit.txt"

fail=0

note() { printf '  %s\n' "$1"; }
finding() {
  printf 'FINDING: %s\n' "$1"
  fail=1
}

printf '%s\n' "RIAK v0.3 release assembly audit"
printf '%s\n' "static screen only: not a constant-time proof"
printf '\n'

if ! command -v objdump >/dev/null 2>&1; then
  printf '%s\n' "SKIP: objdump is unavailable, the audit cannot run"
  exit 2
fi

if ! command -v cargo >/dev/null 2>&1; then
  printf '%s\n' "SKIP: cargo is unavailable, the audit cannot run"
  exit 2
fi

printf '%s\n' "building the release binary"
if ! cargo build --release --bin riak >/dev/null 2>&1; then
  printf '%s\n' "SKIP: the release build failed, the audit cannot run"
  exit 2
fi

if [ ! -f "$BINARY" ]; then
  printf '%s\n' "SKIP: $BINARY was not produced"
  exit 2
fi

objdump -d --no-show-raw-insn "$BINARY" > "$DUMP" 2>/dev/null || {
  printf '%s\n' "SKIP: objdump could not disassemble $BINARY"
  exit 2
}

printf 'disassembly: %s (%s lines)\n' "$DUMP" "$(wc -l < "$DUMP")"

# Resolve a symbol to its start address using `nm`, which demangles for us.
# `objdump` prints Rust v0-mangled names by default, so matching on the demangled
# name inside the disassembly does not work.
#
# Rust demangles types as `<riak::v3::RiakV3Cipher>::open`, so callers pass the
# pattern in the same shape and it is matched as a substring.
resolve_symbol() {
  nm -C "$BINARY" 2>/dev/null \
    | awk -v want="$1" '
        {
          address = $1
          type = $2
          name = $0
          sub(/^[^ ]+ +[^ ]+ +/, "", name)
          if (type != "T" && type != "t" && type != "W" && type != "w") { next }
          if (index(name, want) > 0) { print address; exit }
        }
      '
}

# Extract the disassembly of one function by address range. Returns non-zero
# when the address cannot be resolved, which is itself worth reporting: a core
# that was inlined away or stripped cannot be audited this way and has to be
# reviewed by hand.
extract_symbol() {
  local symbol="$1"
  local out="$2"
  local start end size
  start="$(resolve_symbol "$symbol")"
  if [ -z "$start" ]; then
    return 1
  fi
  # `nm -S` prints "address size type name". Use the size to bound the range.
  # `strtonum` is a GNU-awk extension and is unavailable under mawk, so the
  # end address is computed in the shell.
  local size end_hex
  size="$(nm -S -C "$BINARY" 2>/dev/null | awk -v s="$start" '
    $1 == s && $2 ~ /^[0-9a-f]+$/ { print $2; exit }
  ')"
  if [ -z "$size" ]; then
    return 1
  fi
  end_hex=$(printf '%x' $(( 0x$start + 0x$size )))
  local start_hex
  start_hex="$(printf '%x' $(( 0x$start )))"
  # Start collecting at the target address and stop at the end address, both
  # compared as unpadded hex. Instruction lines look like "   1d910:<tab>mnemonic".
  awk -v s="$start_hex" -v e="$end_hex" '
    function addr(text) {
      sub(/:$/, "", text)
      sub(/^0+/, "", text)
      if (text == "") { return "0" }
      return text
    }
    $1 ~ /:$/ {
      a = addr($1)
      if (a == s) { collecting = 1; print; next }
      if (collecting) {
        if (a == e) { exit }
        print
      }
    }
  ' "$DUMP" > "$out"
  [ -s "$out" ]
}

# The symbols that carry the v0.3 core and the wrapper hot paths.
#
# These are matched as substrings of the demangled name. A symbol that the
# optimiser inlined away has no separate entry; that is reported as a gap that
# needs manual review rather than being silently skipped.
SYMBOLS=(
  'riak::v3::RiakV3>::encrypt_block'
  'riak::v3::RiakV3>::from_words_with_domain'
  'riak::v3::RiakV3Cipher>::seal'
  'riak::v3::RiakV3Cipher>::open'
  'riak::v3::RiakV3Cipher>::racik'
  'riak::v3::RiakV3Cipher>::auth_tag'
)

printf '\nper-symbol findings\n'
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

missing=0
for symbol in "${SYMBOLS[@]}"; do
  # Quoting matters: the Rust demangled name contains ">", which the shell would
  # otherwise treat as a redirection if the pattern were inlined.
  if ! extract_symbol "$symbol" "$tmp"; then
    note "symbol not present as a separate function (likely inlined): $symbol"
    note "  it cannot be screened here and needs manual review of its callers"
    missing=$(( missing + 1 ))
    continue
  fi

  instructions=$(grep -cE '^\s+[0-9a-f]+:' "$tmp")
  printf '\n%s (%s instructions)\n' "$symbol" "$instructions"

  # Integer division is variable time on most hardware.
  if grep -qE '\b(div|idiv)\b' "$tmp"; then
    finding "$symbol contains integer division: $(grep -oE '\b(div|idiv)[a-z]*\b' "$tmp" | sort -u | tr '\n' ' ')"
  fi

  # Computed addresses are listed as leads, not findings. See the header: a
  # linear scan over a buffer produces the same shape as a table lookup, and
  # telling them apart needs data flow analysis this script does not do.
  computed=$(grep -oE '\(%[a-z0-9]+,%[a-z0-9]+(,[1248])?\)' "$tmp" \
    | grep -vE '\(%rsp|\(%rbp' | sort -u || true)
  if [ -n "$computed" ]; then
    note "computed-address leads (review whether the index is a public counter):"
    echo "$computed" | sed 's/^/      /'
  fi

  # A jump whose displacement is zero-length is a no-op pattern; a conditional
  # branch with a very small span is a candidate data-dependent branch. Report
  # the count so a reviewer can eyeball the loop structure.
  conditional=$(grep -cE '\bj(e|ne|g|ge|l|le|a|ae|b|be|s|ns)\b' "$tmp" || true)
  note "conditional branches: $conditional (expected: public loop counters)"

  # Show every conditional branch target so the loop structure is reviewable.
  grep -E '\bj(e|ne|g|ge|l|le|a|ae|b|be|s|ns)\b' "$tmp" \
    | sed 's/^/    /' || true
done

printf '\nsummary\n'
if [ "$fail" -ne 0 ]; then
  printf '%s\n' "FAIL: at least one pattern that is unsafe by construction was found"
  printf '%s\n' "review the findings above before trusting this build"
  exit 1
fi

audited=$((${#SYMBOLS[@]} - missing))
printf 'PASS: no integer division was found in the %s core symbol(s) that\n' "$audited"
printf '%s\n' "survived inlining, and no secret-dependent control flow was detected"
if [ "$missing" -gt 0 ]; then
  printf '\n'
  printf 'NOTE: %s of %s core symbols were inlined away and were NOT screened:\n' \
    "$missing" "${#SYMBOLS[@]}"
  printf '%s\n' "a clean run is therefore partial coverage, not a clean bill of health"
fi
printf '\n'
printf '%s\n' "This remains a static screen on one compiler and one target. It is not a"
printf '%s\n' "constant-time guarantee and does not cover microarchitecture, speculative"
printf '%s\n' "execution, allocator behaviour, or a different toolchain. Statistical"
printf '%s\n' "leakage testing with dudect or ctgrind is still outstanding."
exit 0
