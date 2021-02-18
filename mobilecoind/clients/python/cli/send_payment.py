#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2018-2021 The MobileCoin Foundation

""" transfer funds from a master key to second account (specified by either a key or a b58 address code) """

import argparse
import time
import re

import os, sys

sys.path.insert(1, os.path.realpath(os.path.join(os.path.pardir, "lib")))
import mobilecoin

TX_RECEIPT_CHECK_INTERVAL_SECONDS = 4


def is_b58_sequence(text: str) -> bool:
    match = re.match(
        r"([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)", text.strip()
    )
    return match and len(match.group(0)) == len(text.strip())


if __name__ == "__main__":
    # Connect to mobilecoind
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # Parse the arguments
    parser = argparse.ArgumentParser(
        description="Send all available funds (--all) or a value in pMOB (--value) from a sender's Master Key to a recipient, specified by the recipient's Master Key or Address Code."
    )
    parser.add_argument(
        "--sender", help="sender account master key", type=str, required=True
    )
    parser.add_argument(
        "--recipient",
        help="recipient account master key, or recipient base-58 Address Code",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-v",
        "--value",
        help="(optional) value to send in picoMOB",
        type=int,
        required=False,
    )
    parser.add_argument(
        "-a", "--all", help="(optional) send all available funds", action="store_true"
    )
    parser.add_argument(
        "--sender-subaddress",
        help="(optional) sender subaddress",
        nargs="?",
        const=mobilecoin.DEFAULT_SUBADDRESS_INDEX,
        type=int,
        dest="sender_subaddress",
        default=mobilecoin.DEFAULT_SUBADDRESS_INDEX,
    )
    parser.add_argument(
        "--recipient-subaddress",
        help="(optional) recipient subaddress",
        nargs="?",
        const=mobilecoin.DEFAULT_SUBADDRESS_INDEX,
        type=int,
        dest="recipient_subaddress",
        default=mobilecoin.DEFAULT_SUBADDRESS_INDEX,
    )
    args = parser.parse_args()

    # create a monitor for the sender
    sender_entropy_bytes = bytes.fromhex(args.sender)
    sender_account_key = mobilecoind.get_account_key(sender_entropy_bytes).account_key
    sender_monitor_id = mobilecoind.add_monitor(
        sender_account_key, first_subaddress=args.sender_subaddress
    ).monitor_id

    # if the recipient was provided as a hex key, get the b58 address code
    if not is_b58_sequence(args.recipient):
        recipient_entropy_bytes = bytes.fromhex(args.recipient)
        recipient_account_key = mobilecoind.get_account_key(
            recipient_entropy_bytes
        ).account_key
        recipient_monitor_id = mobilecoind.add_monitor(
            recipient_account_key, first_subaddress=args.recipient_subaddress
        ).monitor_id
        recipient_address_code = mobilecoind.get_public_address(
            recipient_monitor_id, subaddress_index=args.recipient_subaddress
        ).b58_code
        # if the recipient was specified with a master key; we may want to remove it afterwards; see MCC-1891 for details
    else:
        recipient_address_code = args.recipient

    if not args.value and not args.all:
        print(
            "You must provide either an amount to send in picoMOB (--value) or indicate that all available funds should be sent (--all)"
        )
        sys.exit(0)
    elif not args.value:
        (
            monitor_is_behind,
            next_block,
            remote_count,
            blocks_per_second,
        ) = mobilecoind.wait_for_monitor(sender_monitor_id)
        if monitor_is_behind:
            print(
                "#\n# waiting for the monitor to process {} blocks".format(
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
                ) = mobilecoind.wait_for_monitor(sender_monitor_id)
            print("# monitor has processed all {} blocks\n#".format(local_count))

        balance_picoMOB = mobilecoind.get_balance(
            sender_monitor_id, subaddress_index=args.sender_subaddress
        ).balance

        # send as much as possible after accounting for the fee
        value_to_send_picoMOB = balance_picoMOB - mobilecoin.MINIMUM_FEE

        if value_to_send_picoMOB <= 0:
            print(
                "\nSender's balance is too low to cover fee. ({} < {})\n".format(
                    mobilecoin.display_as_MOB(balance_picoMOB),
                    mobilecoin.display_as_MOB(mobilecoin.MINIMUM_FEE),
                )
            )
            sys.exit(0)
    else:
        value_to_send_picoMOB = args.value

    # build and send the payment

    tx_list = mobilecoind.get_unspent_tx_output_list(
        sender_monitor_id, args.sender_subaddress
    ).output_list
    receiver = mobilecoind.parse_address_code(recipient_address_code).receiver
    outlays = [{"value": value_to_send_picoMOB, "receiver": receiver}]
    tx_proposal = mobilecoind.generate_tx(
        sender_monitor_id, args.sender_subaddress, tx_list, outlays
    ).tx_proposal
    sender_tx_receipt = mobilecoind.submit_tx(tx_proposal).sender_tx_receipt
    # Wait for the transaction to clear
    tx_status = mobilecoin.TxStatus.Unknown
    while tx_status == mobilecoin.TxStatus.Unknown:
        time.sleep(TX_RECEIPT_CHECK_INTERVAL_SECONDS)
        tx_status = mobilecoind.get_tx_status_as_sender(sender_tx_receipt).status
        print("Transaction status: {}".format(mobilecoin.parse_tx_status(tx_status)))

    # print summary
    print("\n")
    print("    {:<18}{}".format("Sender:", args.sender))
    print("    {:<18}{}".format("Recipient:", args.recipient))
    print("    {:<18}{} picoMOB".format("Value:", value_to_send_picoMOB))
    print("    {:<18}{}".format(" ", mobilecoin.display_as_MOB(value_to_send_picoMOB)))
    print("\n")
    print("    {:<18}{}".format("Final Status:", mobilecoin.parse_tx_status(tx_status)))
    print("\n")
