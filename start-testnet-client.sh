#!/bin/bash

# Copyright (c) 2018-2021 The MobileCoin Foundation
#
# Launches a local `mc-mobilecoind` instance that syncs the ledger from two nodes in the
# test network and hosts a wallet service running on port 4444, then launches a local
# `mc-testnet-client` instance that interacts with the local `mc-mobilecoind`.

set -e

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

source "$HOME/.cargo/env"

pushd "$(dirname "$0")"

echo "Pulling down TestNet consensus validator signature material"

SIGSTRUCT_URI=$(curl -s https://enclave-distribution.test.mobilecoin.com/production.json | grep sigstruct | awk '{print $2}' | tr -d \")
curl -O https://enclave-distribution.test.mobilecoin.com/${SIGSTRUCT_URI}

TARGETDIR=./target/release

echo "Building mobilecoind and mc-mobilecoind-json. This will take a few moments."
SGX_MODE=HW IAS_MODE=PROD CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css \
        cargo build --release -p mc-mobilecoind -p mc-mobilecoind-json

if [[ -f /tmp/ledger-db ]] || [[ -f /tmp/transaction-db ]]; then
    echo "Removing ledger-db and transaction_db from previous runs. Comment out this line to keep them for future runs."
    rm -rf /tmp/ledger-db; rm -rf /tmp/transaction-db; mkdir /tmp/transaction-db
fi

echo "Starting local mobilecoind using TestNet servers for source of ledger. Check log at $(pwd)/mobilecoind.log."
${TARGETDIR}/mobilecoind \
        --ledger-db /tmp/ledger-db \
        --poll-interval 10 \
        --peer mc://node1.test.mobilecoin.com/ \
        --peer mc://node2.test.mobilecoin.com/ \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
        --mobilecoind-db /tmp/transaction-db \
        --listen-uri insecure-mobilecoind://127.0.0.1:4444/ &> $(pwd)/mobilecoind.log &

pid=$!

sleep 2
if ps -p $pid > /dev/null; then
    echo "Sleeping 5s to allow mobilecoind to sync the ledger"
    sleep 5

    echo "Starting local mobilecoind-json."
    ${TARGETDIR}/mobilecoind-json
else
    echo "Starting mobilecoind failed. Please check logs at $(pwd)/mobilecoind.log."
fi

popd
