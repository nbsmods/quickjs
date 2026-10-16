#!/bin/sh
# Build and run the Luna bytecode format + mod loader tests.
#
# Usage: ./run-luna-tests.sh [build-dir]
set -e

BUILD=${1:-/tmp/luna-tests}
CC=${CC:-gcc}
QJSC=./qjsc

mkdir -p "$BUILD"

echo "== building qjsc (patched compiler) =="
make qjsc -j4 >/dev/null

echo "== codec tests (crypto, container, permutation) =="
$CC -O2 -g -Wall -o "$BUILD/luna_bc_test" luna_bc_test.c luna_bc.c -lm
"$BUILD/luna_bc_test"

echo "== engine round trip (compile, seal, decrypt, execute) =="
$CC -O2 -g -Wall -o "$BUILD/luna_engine_test" luna_engine_test.c quickjs.c \
    libregexp.c libunicode.c cutils.c libbf.c quickjs-libc.c luna_bc.c \
    -DCONFIG_VERSION="\"test\"" -DCONFIG_BIGNUM -D_GNU_SOURCE -lm -ldl -lpthread
"$BUILD/luna_engine_test"

echo "== mod loader tests (discovery, deps, cross mod imports) =="
$CC -O2 -g -Wall -o "$BUILD/luna_mods_test" -DLUNA_GC_DEBUG \
    luna_mods_test.c luna_mods.c quickjs.c libregexp.c libunicode.c cutils.c \
    libbf.c quickjs-libc.c luna_bc.c \
    -DCONFIG_VERSION="\"test\"" -DCONFIG_BIGNUM -D_GNU_SOURCE -lm -ldl -lpthread
LUNA_MOD_PATHS="$BUILD/mods" "$BUILD/luna_mods_test"

echo "== differential fuzz (stock vs sealed, random programs) =="
$CC -O2 -g -Wall -o "$BUILD/luna_fuzz_test" luna_fuzz_test.c quickjs.c \
    libregexp.c libunicode.c cutils.c libbf.c quickjs-libc.c luna_bc.c \
    -DCONFIG_VERSION="\"test\"" -DCONFIG_BIGNUM -D_GNU_SOURCE -lm -ldl -lpthread
"$BUILD/luna_fuzz_test" "${LUNA_FUZZ_ITERS:-1000}"

echo "all Luna tests passed"
