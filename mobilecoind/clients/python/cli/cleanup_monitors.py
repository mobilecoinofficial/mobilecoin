#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2018-2021 The MobileCoin Foundation

""" displays information about all active monitors and prompt the user to keep or remove each """

import os, sys

sys.path.insert(1, os.path.realpath(os.path.join(os.path.pardir, "lib")))
import mobilecoin


def confirm_remove_monitor():
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    while True:
        sys.stdout.write("    Remove this monitor? [y/N]")
        choice = input().lower()
        if choice == "":
            return valid["no"]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("    Please respond with 'yes' or 'no'.\n")


if __name__ == "__main__":
    # Connect to mobilecoind
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    monitor_list = mobilecoind.get_monitor_list().monitor_id_list
    # show a summary of all monitors
    if len(monitor_list) == 0:
        print("\n    There no active monitors.\n")
        sys.exit(0)
    elif len(monitor_list) == 1:
        print("\n    There is 1 active monitor.\n")
    else:
        print("\n    There are {} active monitors.\n".format(len(monitor_list)))
        print(
            "    {:<18}{:<18}{:<18}".format(
                "Monitor ID", "Subaddress Range", "Next Block"
            )
        )
        for monitor_id in monitor_list:
            # check monitor status
            status = mobilecoind.get_monitor_status(monitor_id).status
            first_subaddress: int = (
                status.first_subaddress if hasattr(status, "first_subaddress") else 0
            )
            num_subaddresses: int = (
                status.num_subaddresses if hasattr(status, "num_subaddresses") else 0
            )
            last_subaddress: int = first_subaddress + num_subaddresses - 1
            next_block: int = status.next_block if hasattr(status, "next_block") else 0
            print(
                "    {:<18}{:<18}{:<18}".format(
                    monitor_id.hex()[0:10] + "...",
                    "{} to {}".format(first_subaddress, last_subaddress),
                    next_block,
                )
            )
        print("\n    Choose monitors to be remove...")

    # iterate over all active monitors
    for monitor_id in monitor_list:
        # check ledger status
        network_status_response = self.get_network_status()
        remote_count = network_status_response.network_highest_block_index
        local_count = network_status_response.local_block_index
        ledger_is_behind = network_status_response.is_behind

        # check monitor status
        status = mobilecoind.get_monitor_status(monitor_id).status

        # get fields (protobuf omits fields with empty or zero values)
        account_key = status.account_key if hasattr(status, "account_key") else None
        first_subaddress: int = (
            status.first_subaddress if hasattr(status, "first_subaddress") else 0
        )
        num_subaddresses: int = (
            status.num_subaddresses if hasattr(status, "num_subaddresses") else 0
        )
        first_block: int = status.first_block if hasattr(status, "first_block") else 0
        next_block: int = status.next_block if hasattr(status, "next_block") else 0
        name: str = status.name if hasattr(status, "name") else ""

        print("\n")
        print("    {:<18}{}".format("Monitor ID:", monitor_id.hex()[0:10] + "..."))
        if name:
            print("    {:<18}{}".format("Monitor Name:", name))
        print("    {:<18}{}".format("First Block:", first_block))
        print(
            "    {:<18}{} (ledger has {}/{} blocks)".format(
                "Next Block:", status.next_block, local_count, remote_count
            )
        )
        print("    {:<18}{}".format("Subaddress Count:", num_subaddresses))
        print("    {:<18}{}".format("First Subaddress:", first_subaddress))
        print()
        print("    {:<18}{:<20}".format("Address Code", "Balance (pMOB)", "Balance"))
        for subaddress_index in range(
            first_subaddress, first_subaddress + min(10, num_subaddresses)
        ):
            address_code = mobilecoind.get_public_address(
                monitor_id, subaddress_index=subaddress_index
            ).b58_code
            balance_picoMOB = mobilecoind.get_balance(
                monitor_id, subaddress_index=subaddress_index
            ).balance
            print(
                "    {:<18}{:<20}{:<20}".format(
                    address_code[0:10] + "...",
                    balance_picoMOB,
                    mobilecoin.display_as_MOB(balance_picoMOB),
                )
            )
        print("\n")

        if confirm_remove_monitor():
            print("    Removing monitor_id {}\n".format(monitor_id.hex()[0:10] + "..."))
            mobilecoind.remove_monitor(monitor_id)
        else:
            print()
