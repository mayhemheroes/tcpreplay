#!/usr/bin/env bash
#
# mayhem/test.sh — run tcpreplay's OWN upstream functional test suite (test/Makefile.am), already
# built by mayhem/build.sh (the normal, unsanitized tcpprep/tcprewrite/tcpreplay in src/).
#
# The upstream suite (`make -C test test`) is a set of golden-output tests: each target runs a tool
# and `diff`s its output against a committed reference file (test/test.*), so it asserts BEHAVIOUR —
# a program neutered to exit(0) produces no/empty output and every diff FAILS. We drive each test as
# its own `make <target>` and use make's exit status (the recipe runs `false` on a diff mismatch).
#
# Privileged tests are SKIPPED, not faked: tcpreplay's live-replay tests inject packets on a real NIC
# and the suite itself prints "NOTICE: Tests must be run as root". Those need root + a network
# interface that the Mayhem build/CI container does not have, so they are counted as skipped with the
# reason recorded here. The three file-output replay tests (-w to a file, no injection) DO run.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

for b in src/tcpprep src/tcprewrite src/tcpreplay; do
  if [ ! -x "$b" ]; then
    echo "FATAL: $b missing — mayhem/build.sh did not build the normal tools" >&2
    emit_ctrf tcpreplay-suite 0 1 0; exit 1
  fi
done

# tcpprep (all file-based) + tcprewrite (all file-based) + the file-output replay tests.
PREP="auto_router auto_bridge auto_client auto_server auto_first cidr regex port mac comment \
print_info print_comment prep_config mac_reverse cidr_reverse regex_reverse exclude_packets \
include_packets include_source include_dest"
REWRITE="rewrite_portmap rewrite_range_portmap rewrite_endpoint rewrite_pnat rewrite_trunc \
rewrite_pad rewrite_seed rewrite_mac rewrite_layer2 rewrite_config rewrite_skip rewrite_dltuser \
rewrite_dlthdlc rewrite_vlan802.1ad rewrite_vlandel rewrite_efcs rewrite_1ttl rewrite_2ttl \
rewrite_3ttl rewrite_1ttl-hdrfix rewrite_2ttl-hdrfix rewrite_3ttl-hdrfix rewrite_tos \
rewrite_mtutrunc rewrite_enet_subsmac rewrite_mac_seed rewrite_mac_seed_keep rewrite_l7fuzzing \
rewrite_sequence rewrite_fixcsum rewrite_fixlen_pad rewrite_fixlen_trunc rewrite_fixlen_del"
REPLAY_FILE="replay_include replay_exclude replay_unique_ip"
# Privileged: live packet injection on a NIC as root — unavailable in the container. Skipped.
REPLAY_PRIV="replay_basic replay_nano_timer replay_cache replay_pps replay_rate replay_top \
replay_config replay_multi replay_pps_multi replay_precache replay_stats replay_dualfile \
replay_maxsleep"

passed=0; failed=0; failed_names=""
# Remove any stale generated outputs (*1 files) FIRST — the commit image already ran this suite at
# build time, so leftover golden outputs could let a neutered binary "pass" a diff it never produced.
# `make clean` is upstream's own target: rm -f *1 test.log core* *~ primary.data secondary.data.
make -C test clean >/dev/null 2>&1 || true
for t in $PREP $REWRITE $REPLAY_FILE; do
  if make -C test "$t" >/dev/null 2>&1; then
    passed=$((passed+1))
  else
    failed=$((failed+1)); failed_names="$failed_names $t"
  fi
done

skipped=0
for t in $REPLAY_PRIV; do skipped=$((skipped+1)); done

echo "=== tcpreplay upstream suite ==="
echo "passed=$passed failed=$failed skipped=$skipped (privileged live-replay: needs root + NIC)"
[ -n "$failed_names" ] && echo "FAILED:$failed_names"
echo "skipped (root/NIC packet injection):$REPLAY_PRIV"

emit_ctrf tcpreplay-suite "$passed" "$failed" "$skipped"
