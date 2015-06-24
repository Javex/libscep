#!/bin/sh -e
exec 2>&1
set -x
PREFIX="$1"
if [ -n "$2" ]; then
    BOTAN_PREFIX="--with-botan=$2"
    LDFLAGS="-Wl,-rpath,'$2/lib'"
fi

git submodule update SoftHSMv1
cd SoftHSMv1
sh autogen.sh
./configure $BOTAN_PREFIX --prefix="$PREFIX"
make LDFLAGS="$LDFLAGS"
make install