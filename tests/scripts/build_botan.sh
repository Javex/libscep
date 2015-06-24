#!/bin/sh -e
exec 2>&1
set -x
PREFIX="$1"
PYVER=$(python -c 'import sys; print(sys.version_info.major)')
case "$PYVER" in
    "3")
        PYTHON="$(which python2)"
        ;;
    "2")
        PYTHON="$(which python)"
        ;;
    *)
        echo "Python not found!"
        exit 1
        ;;
esac

git submodule update botan
cd botan
$PYTHON configure.py --prefix "$PREFIX"
make
make install