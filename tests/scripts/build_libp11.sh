#!/bin/sh -e
exec 2>&1
set -x
PREFIX="$1"
cd "$(git rev-parse --show-toplevel)"
git submodule update --init tests/submodules/libp11
cd tests/submodules/libp11
./bootstrap
./configure --prefix="$PREFIX"
make
make install