#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2018-2021 The MobileCoin Foundation

""" displays the balance for a provided master key """

import argparse

import os, sys

sys.path.insert(1, os.path.realpath(os.path.join(os.path.pardir, "lib")))
import mobilecoin

if __name__ == "__main__":
    # Connect to mobilecoind
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # Parse the arguments
    parser = argparse.ArgumentParser(
        description="Processes all downloaded blocks to display current balance information for a provided master key."
    )
    parser.add_argument(
        "-k", "--key", help="account master key", type=str, required=True
    )
    parser.add_argument(
        "-s",
        "--subaddress",
        help="(optional) subaddress",
        nargs="?",
        const=mobilecoin.DEFAULT_SUBADDRESS_INDEX,
        type=int,
        default=mobilecoin.DEFAULT_SUBADDRESS_INDEX,
    )
    parser.add_argument(
        "--first-block",
        help="(optional) first ledger block to scan",
        nargs="?",
        const=0,
        type=int,
        dest="first_block",
        default=0,
    )
    args = parser.parse_args()

    # create a monitor
    entropy_bytes = bytes.fromhex(args.key)
    account_key = mobilecoind.get_account_key(entropy_bytes).account_key
    monitor_id = mobilecoind.add_monitor(
        account_key, first_subaddress=args.subaddress, first_block=args.first_block
    ).monitor_id

    # Wait for the monitor to process the complete ledger (this also downloads the complete ledger)
    (
        monitor_is_behind,
        next_block,
        remote_count,
        blocks_per_second,
    ) = mobilecoind.wait_for_monitor(monitor_id)
    if monitor_is_behind:
        print(
            "\n# waiting for the monitor to process {} blocks".format(
                remote_count - next_block
            )
        )
        while monitor_is_behind:
            blocks_remaining = remote_count - next_block
            if blocks_per_second > 0:
                time_remaining_seconds = blocks_remaining / blocks_per_second
                print(
                    "#    {} blocks remain ({} seconds)".format(
                        blocks_remaining, round(time_remaining_seconds, 1)
                    )
                )
            else:
                print("#    {} blocks remain (? seconds)".format(blocks_remaining))
            (
                monitor_is_behind,
                next_block,
                remote_count,
                blocks_per_second,
            ) = mobilecoind.wait_for_monitor(
                monitor_id, max_blocks_to_sync=2000, timeout_seconds=20
            )
        print("# monitor has processed all {} blocks\n".format(remote_count))

    balance_picoMOB = mobilecoind.get_balance(
        monitor_id, subaddress_index=args.subaddress
    ).balance
    public_address = mobilecoind.get_public_address(
        monitor_id, subaddress_index=args.subaddress
    ).public_address

    # print account information
    print("\n")
    print("    {:<18}{}".format("Master Key:", args.key))
    print("    {:<18}{}".format("Subaddress Index:", args.subaddress))
    print("    {:<18}{}".format("Address Code:", public_address.b58_code))
    print("    {:<18}{}".format("Address URL:", "mob58://" + public_address.b58_code))
    print("    {:<18}{} pMOB".format("Balance:", balance_picoMOB))
    print("    {:<18}{}".format(" ", mobilecoin.display_as_MOB(balance_picoMOB)))
    print("\n")
