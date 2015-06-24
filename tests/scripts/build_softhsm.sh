#!/bin/sh -e
exec 2>&1
set -x
PREFIX="$1"
if [ -n "$2" ]; then
    BOTAN_PREFIX="--with-botan=$2"
    LDFLAGS="-Wl,-rpath,'$2/lib'"
fi

cd "$(git rev-parse --show-toplevel)"
git submodule update --init tests/submodules/SoftHSMv1
cd tests/submodules/SoftHSMv1
sh autogen.sh
./configure $BOTAN_PREFIX --prefix="$PREFIX"
make LDFLAGS="$LDFLAGS"
make install