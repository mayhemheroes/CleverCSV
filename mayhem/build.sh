#!/usr/bin/env bash
#
# mayhem/build.sh — build the CleverCSV Atheris fuzz harness (PyInstaller onefile ELF) and test oracle.
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem.
#
# PyInstaller bundles Python+atheris into one ELF so Mayhem can collect edges_covered (>0).
#
# AIR-GAPPED CONTRACT: the PATCH tier re-runs THIS script OFFLINE.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

PY_PREFIX=/opt/toolchains/python
WHEELHOUSE="$PY_PREFIX/wheelhouse"
PY="$(command -v python3)"
WHEELHOUSE_STAMP="$WHEELHOUSE/.populated"

graft_dwarf() {
  local bin="$1"
  # shellcheck disable=SC2086
  $CC -c $DEBUG_FLAGS "$SRC/mayhem/asan_defaults.c" -o /tmp/dwarf_anchor.o
  for sect in .debug_info .debug_abbrev .debug_line .debug_str; do
    if objcopy --dump-section "${sect}=/tmp/dwarf_sect.bin" /tmp/dwarf_anchor.o 2>/dev/null; then
      objcopy --add-section "${sect}=/tmp/dwarf_sect.bin" \
        --set-section-flags "${sect}=alloc,merge,debug" "$bin" /tmp/bin_grafted
      mv /tmp/bin_grafted "$bin"
    fi
  done
}

mkdir -p "$WHEELHOUSE"
if [ -f "$WHEELHOUSE_STAMP" ]; then
  echo ">> wheelhouse already populated — reusing (air-gapped re-run path)"
else
  echo ">> populating wheelhouse (online) at $WHEELHOUSE"
  "$PY" -m pip download --dest "$WHEELHOUSE" atheris pyinstaller wheel setuptools build packaging
  "$PY" -m pip download --dest "$WHEELHOUSE" .
  "$PY" -m pip download --dest "$WHEELHOUSE" ".[test]"
  touch "$WHEELHOUSE_STAMP"
fi

if [ -x /mayhem/test-venv/bin/python3 ] \
   && /mayhem/test-venv/bin/python3 -c "import clevercsv.cparser; import pandas" 2>/dev/null; then
  echo ">> test venv already ready — skipping"
else
  echo ">> installing clevercsv for test oracle (clean)"
  python3 -m venv /mayhem/test-venv
  /mayhem/test-venv/bin/pip install --upgrade pip wheel
  (
    unset CFLAGS CXXFLAGS LDFLAGS
    /mayhem/test-venv/bin/pip install --no-index --find-links="$WHEELHOUSE" -e ".[test]" 2>/dev/null \
      || /mayhem/test-venv/bin/pip install -e ".[test]"
  )
fi

if [ -x /mayhem/read-fuzz ] && /mayhem/fuzz-venv/bin/python3 -c "import atheris" 2>/dev/null; then
  echo ">> read-fuzz ELF already built — skipping PyInstaller (idempotent re-run)"
else
  echo ">> building read-fuzz PyInstaller ELF"
  python3 -m venv /mayhem/fuzz-venv
  /mayhem/fuzz-venv/bin/pip install --upgrade pip wheel
  /mayhem/fuzz-venv/bin/pip install --no-index --find-links="$WHEELHOUSE" setuptools build wheel 2>/dev/null \
    || /mayhem/fuzz-venv/bin/pip install setuptools build wheel
  export CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" CXXFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" LDFLAGS="$SANITIZER_FLAGS"
  /mayhem/fuzz-venv/bin/pip install --no-index --find-links="$WHEELHOUSE" atheris pyinstaller 2>/dev/null \
    || /mayhem/fuzz-venv/bin/pip install atheris pyinstaller
  (
    unset CFLAGS CXXFLAGS LDFLAGS
    /mayhem/fuzz-venv/bin/pip install --no-index --find-links="$WHEELHOUSE" . 2>/dev/null \
      || /mayhem/fuzz-venv/bin/pip install .
  )

  # shellcheck disable=SC2086
  $CC -shared -fPIC $DEBUG_FLAGS -o /mayhem/asan_defaults.so "$SRC/mayhem/asan_defaults.c"

  /mayhem/fuzz-venv/bin/pyinstaller \
    --distpath /tmp/pyinst-out \
    --workpath /tmp/pyinst-work \
    --specpath /tmp/pyinst-spec \
    --onefile \
    --name read-fuzz \
    --collect-all clevercsv \
    --add-binary /mayhem/asan_defaults.so:. \
    "$SRC/mayhem/fuzz_reader.py"

  install -m 0755 /tmp/pyinst-out/read-fuzz /mayhem/read-fuzz
  graft_dwarf /mayhem/read-fuzz
fi

if [ -x "$SRC/run_tests" ]; then
  echo ">> run_tests already built — skipping"
else
  echo ">> compiling run_tests ELF test runner"
  # shellcheck disable=SC2086
  $CC -c $DEBUG_FLAGS "$SRC/mayhem/asan_defaults.c" -o /tmp/asan_defaults.o
  # shellcheck disable=SC2086
  $CC $DEBUG_FLAGS \
    "$SRC/mayhem/run_tests.c" /tmp/asan_defaults.o \
    -o "$SRC/run_tests"
  chmod +x "$SRC/run_tests"
fi

echo ">> build.sh complete"
ls -la /mayhem/read-fuzz "$SRC/run_tests"
