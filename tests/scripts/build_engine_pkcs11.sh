#!/bin/sh -e
exec 2>&1
set -x
PREFIX="$1"
PKG_CONFIG_PATH="$2"
git submodule update engine_pkcs11
cd engine_pkcs11
./bootstrap
./configure PKG_CONFIG_PATH="$PKG_CONFIG_PATH" --prefix="$PREFIX"
make CFLAGS="-DOPENSSL_NO_ECDSA"
make install