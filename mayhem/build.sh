#!/usr/bin/env bash
#
# mayhem/build.sh — build tcpreplay's fuzz targets AND its upstream functional test suite.
#
# Two Mayhem targets (historical names preserved):
#   tcpcapinfo   — the upstream pcap-info CLI, a natural file-input parser, built sanitized so
#                  Mayhem fuzzes the real pcap-parsing code path (@@ file input).
#   dualmac2hex  — an in-process libFuzzer harness over common/mac.c:dualmac2hex(), linked against
#                  the sanitized libcommon.a.
#
# The fuzzed code (libcommon + tcpcapinfo) is built with $SANITIZER_FLAGS + $DEBUG_FLAGS. The test
# suite (tcpprep/tcprewrite/tcpreplay) is built SEPARATELY with the project's normal flags so
# mayhem/test.sh only RUNS it and won't false-fail on benign UB. autogen (the AutoOpts generator),
# libpcap and the system libopts are provided by the image (installed as root in mayhem/Dockerfile).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

INSTALL_PREFIX=/mayhem/install
COMMON_A="$SRC/src/common/libcommon.a"
HARNESS="$SRC/mayhem/fuzz_dualmac2hex.cpp"

# 1) SANITIZED build — instrument the fuzzed code (libcommon.a + the tcpcapinfo CLI). Build only the
#    artifacts the fuzz targets need (skip the man-page/all targets, which need groff-style tooling).
./autogen.sh
./configure CC="$CC" CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
    --disable-local-libopts --prefix="$INSTALL_PREFIX"
make -C src/common -j"$MAYHEM_JOBS"
# The AutoOpts *_opts.{c,h} are generated at build time; a parallel `make` can start compiling the
# tool before its generated header is fully written ("unterminated /* comment"). Build the tools
# serially so the generation ordering holds.
make -C src tcpcapinfo
install -D -m0755 "$SRC/src/tcpcapinfo" "$INSTALL_PREFIX/bin/tcpcapinfo"

# 2) dualmac2hex harness — fuzzer binary + standalone (run-once, no libFuzzer runtime) reproducer.
#    The C++ harness keeps LLVMFuzzerTestOneInput at C linkage; compile the standalone main as C.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$HARNESS" "$COMMON_A" -lpcap -o /mayhem/fuzz_dualmac2hex
$CC  $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$HARNESS" /tmp/standalone_main.o "$COMMON_A" -lpcap -o /mayhem/fuzz_dualmac2hex-standalone

# 3) NORMAL build of the tools the upstream test suite drives (independent, unsanitized). Left in
#    $SRC/src for mayhem/test.sh. distclean drops the sanitized config; regenerate + reconfigure.
make distclean
./autogen.sh
env -u CFLAGS -u LDFLAGS ./configure --disable-local-libopts CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
make -C src/common -j"$MAYHEM_JOBS"
make -C src/tcpedit -j"$MAYHEM_JOBS"
make -C src tcpprep tcprewrite tcpreplay
