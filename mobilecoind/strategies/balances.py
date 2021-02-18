#!/usr/bin/env python3

# Copyright (c) 2018-2021 The MobileCoin Foundation

"""
The purpose of this script is to print the balances for all keys in
a given account directory.

Example setup and usage:
```
    python3 balances.py --key-dir ../../../target/sample_data/master/keys/
```
"""
import argparse
import grpc
import mobilecoind_api_pb2
import mobilecoind_api_pb2_grpc
import os
from accounts import connect, load_key_and_register
from google.protobuf.empty_pb2 import Empty


def parse_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mobilecoind-host", default="localhost", type=str, help="Mobilecoind host"
    )
    parser.add_argument(
        "--mobilecoind-port", default="4444", type=str, help="Mobilecoind port"
    )
    parser.add_argument(
        "--key-dir", required=True, type=str, help="Path to account key dir"
    )
    parser.add_argument(
        "--prune",
        action="store_true",
        help="Prune key files for accounts with 0 balance",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(args)

    stub = connect(args.mobilecoind_host, args.mobilecoind_port)
    block_count = stub.GetLedgerInfo(Empty()).block_count
    total = 0
    for keyfile in sorted(
        filter(lambda x: x.endswith(".json"), os.listdir(args.key_dir))
    ):
        print(keyfile)

        account_data = load_key_and_register(os.path.join(args.key_dir, keyfile), stub)

        # Get starting balance
        request = mobilecoind_api_pb2.GetMonitorStatusRequest(
            monitor_id=account_data.monitor_id
        )
        monitor_block = stub.GetMonitorStatus(request).status.next_block
        if block_count != monitor_block:
            print(f"\tAccount not synced.")
        else:
            resp = stub.GetBalance(
                mobilecoind_api_pb2.GetBalanceRequest(
                    monitor_id=account_data.monitor_id
                )
            )
            balance = resp.balance
            total += balance
            print(f"\tBalance: {resp.balance:,}")
            # Remove balances of 0 FIXME: MC-367 also from mobilecoind wallet
            if int(balance) == 0 and args.prune:
                os.remove(os.path.join(args.key_dir, keyfile))
    print(f"Total balance of key collection: {total:,} PicoMob")
