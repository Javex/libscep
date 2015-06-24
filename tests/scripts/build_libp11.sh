#!/bin/sh -e
exec 2>&1
set -x
PREFIX="$1"
git submodule update libp11
cd libp11
./bootstrap
./configure --prefix="$PREFIX"
make
make install