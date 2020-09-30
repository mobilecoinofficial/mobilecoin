#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

# transfer funds from a master key to second account (specified by either a key or a b58 address code)

import argparse
import mobilecoin
import time

TX_RECEIPT_CHECK_INTERVAL_SECONDS = 4

def is_b58_sequence(text: str) -> bool:
    match = re.match(r"([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)", text.strip())
    return  match and len(match.group(0)) == len(text.strip())

if __name__ == '__main__':
    # Connect to mobilecoind
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # Parse the arguments
    parser = argparse.ArgumentParser(description='You must provide sender and recipient details.')
    parser.add_argument('--sender', help='sender account master key', type=str)
    parser.add_argument('--recipient', help='recipient account master key or b58 address code', type=str)
    parser.add_argument('--amount', help='optional amount in picoMOB (defaults to all funds)', type=int, required=False)
    parser.add_argument('--sender-subaddress', help='(optional) sender subaddress', nargs='?', const=mobilecoind.DEFAULT_SUBADDRESS_INDEX, type=int, dest='sender_subaddress')
    parser.add_argument('--recipient-subaddress', help='(optional) recipient subaddress', nargs='?', const=mobilecoind.DEFAULT_SUBADDRESS_INDEX, type=int, dest='recipient_subaddress')
    args = parser.parse_args()

    # create a monitor for the sender
    sender_entropy_bytes = bytes.fromhex(args.sender)
    sender_account_key = mobilecoind.get_account_key(sender_entropy_bytes)
    sender_monitor_id = mobilecoind.add_monitor(sender_account_key, first_subaddress=args.sender_subaddress)

    # if the recipient was provided as a hex key, get the b58 address code
    if not is_b58_sequence(args.recipient):
        recipient_entropy_bytes = bytes.fromhex(args.recipient)
        recipient_account_key = mobilecoind.get_account_key(recipient_entropy_bytes)
        recipient_monitor_id = mobilecoind.add_monitor(recipient_account_key, first_subaddress=args.recipient_subaddress)
        recipient_address_code = mobilecoind.get_public_address(recipient_monitor_id, subaddress_index=args.recipient_subaddress).b58_code
    else:
        recipient_address_code = args.recipient

    # if no amount was provided, check the sender's balance
    if not args.amount:
        (monitor_is_behind, next_block, remote_count, blocks_per_second) = mobilecoind.wait_for_monitor(sender_monitor_id)
        if monitor_is_behind:
            print("#\n# waiting for the monitor to process {} blocks".format(remote_count - next_block))
            while monitor_is_behind:
                blocks_remaining = (remote_count - next_block)
                if blocks_per_second > 0:
                    time_remaining_seconds = blocks_remaining / blocks_per_second
                    print("#    {} blocks remain ({} seconds)".format(blocks_remaining, round(time_remaining_seconds, 1)))
                else:
                    print("#    {} blocks remain (? seconds)".format(blocks_remaining))
                (monitor_is_behind, next_block, remote_count, blocks_per_second) = mobilecoind.wait_for_monitor(sender_monitor_id)
            print("# monitor has processed all {} blocks\n#".format(local_count))

        balance_picoMOB = mobilecoind.get_balance(sender_monitor_id, subaddress_index=args.sender_subaddress)

        # send as much as possible after accounting for the fee
        amount_to_send_picoMOB = balance_picoMOB - mobilecoind.MINIMUM_FEE

    else:
        amount_to_send_picoMOB = args.amount

    # build and send the payment

    tx_list = mobilecoind.get_unspent_tx_output_list(sender_monitor_id, args.sender_subaddress)
    recipient_public_address = mobilecoind.parse_address_code(recipient_address_code)
    outlays = [{'value': amount_to_send_picoMOB, 'receiver': recipient_public_address}]
    tx_proposal = mobilecoind.generate_tx(sender_monitor_id, args.sender_subaddress, tx_list, outlays)
    sender_tx_receipt = mobilecoind.submit_tx(tx_proposal).sender_tx_receipt
    # Wait for the transaction to clear
    tx_status = int(mobilecoind.get_tx_status_as_sender(sender_tx_receipt))
    while tx_status == mobilecoind.TX_STATUS_UNKNOWN:
        time.sleep(TX_RECEIPT_CHECK_INTERVAL_SECONDS)

    if tx_status == mobilecoind.TX_STATUS_VERIFIED:
        transaction_status = "Verified"
    elif tx_status == mobilecoind.TX_STATUS_TOMBSTONE_BLOCK_EXCEEDED:
        transaction_status = "Tombstone Block Exceeded"
    elif tx_status == mobilecoind.TX_STATUS_INVALID_CONFIRMATION_NUMBER:
        transaction_status = "Invalid Confirmation Number"
    else:
        transaction_status = "ERROR: Unexpected STATUS CODE {}".format(tx_status)

    # print summary
    print("\n")
    print("    {:<18}{}".format("Sender:", args.sender))
    print("    {:<18}{}".format("Recipient:", args.recipient))
    print("    {:<18}{} picoMOB".format("Amount:", amount_to_send_picoMOB))
    print("    {:<18}{} MOB".format(" ", display_in_MOB(amount_to_send_picoMOB)))
    print("\n")
    print("    {:<18}{}".format("Final Status:", transaction_status)
    print("\n")