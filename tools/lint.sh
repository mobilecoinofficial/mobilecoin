#!/bin/bash

# Copyright (c) 2018-2021 The MobileCoin Foundation

set -e

if [[ ! -z "$1" ]]; then
    cd "$1"
fi

for toml in $(grep --exclude-dir cargo --exclude-dir rust-mbedtls --include=Cargo.toml -r . -e '\[workspace\]' | cut -d: -f1); do
  pushd $(dirname $toml) >/dev/null
  echo "Linting in $PWD"
  cargo fmt -- --unstable-features --check
  cargo clippy --all --all-features
  echo "Linting in $PWD complete."
  popd >/dev/null
  echo "Linting all python" 
  PYTHON_FILES=$(find . -name '*.py'|grep -v cargo)
  black --check mob ${PYTHON_FILES}
done
