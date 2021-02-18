# Copyright (c) 2018-2021 The MobileCoin Foundation

import grpc
import json
import time
import os
import uuid
import mobilecoind_api_pb2
import mobilecoind_api_pb2_grpc
from collections import namedtuple
from enum import Enum
from random import randint
from google.protobuf.empty_pb2 import Empty

AccountData = namedtuple("AccountData", ["account_key", "monitor_id", "public_address"])


class TransferStatus(Enum):
    pending = 0
    success = 1
    tombstoned = 2
    failed = 3


def connect(host, port):
    # Set Up GRPC connection to wallet
    if port == "443":
        credentials = grpc.ssl_channel_credentials()
        channel = grpc.secure_channel("{}:{}".format(host, port), credentials)
    else:
        channel = grpc.insecure_channel("{}:{}".format(host, port))

    return mobilecoind_api_pb2_grpc.MobilecoindAPIStub(channel)


def register_account(key_data, stub) -> AccountData:
    # Generate an account key from this root entropy
    resp = stub.GetAccountKey(
        mobilecoind_api_pb2.GetAccountKeyRequest(
            entropy=bytes(key_data["root_entropy"])
        )
    )
    account_key = resp.account_key

    # Add this account to the wallet
    resp = stub.AddMonitor(
        mobilecoind_api_pb2.AddMonitorRequest(
            account_key=account_key, first_subaddress=0, num_subaddresses=1
        )
    )
    monitor_id = resp.monitor_id

    resp = stub.GetPublicAddress(
        mobilecoind_api_pb2.GetPublicAddressRequest(
            monitor_id=monitor_id, subaddress_index=0
        )
    )
    public_address = resp.public_address

    return AccountData(account_key, monitor_id, public_address)


def load_key_and_register(keyfile, stub) -> AccountData:
    # Load the account key from file
    with open(keyfile, "r") as f:
        key_data = json.load(f)
    # Remove discovery fqdn, as this causes InvalidTxOutMembershipProof
    key_data["acct_fqdn"] = None
    return register_account(key_data, stub)


def register_random_key(stub, outdir) -> AccountData:
    entropy = [randint(0, 255) for i in range(32)]
    print("entropy = ", entropy)
    data = {"root_entropy": entropy}
    outfile = "account_keys_{}.json".format(uuid.uuid4())
    with open(os.path.join(outdir, outfile), "w") as out:
        json.dump(data, out)
    return register_account(data, stub)


def wait_for_accounts_sync(stub, accounts, wait_secs):
    print("accounts = ", accounts[0])
    block_count = stub.GetLedgerInfo(Empty()).block_count
    synced_ids = {a: False for a in accounts}
    while not all(synced_ids.values()):
        print(".", end="", flush=True)
        for a in synced_ids:
            request = mobilecoind_api_pb2.GetMonitorStatusRequest(monitor_id=a)
            monitor_block = stub.GetMonitorStatus(request).status.next_block
            if monitor_block == block_count:
                synced_ids[a] = True
        time.sleep(wait_secs)
    print("All accounts synced")


def get_synced_accounts(stub, accounts):
    block_count = stub.GetLedgerInfo(Empty()).block_count
    synced = {a: False for a in accounts}
    while not any(synced.values()):
        print(".", end="", flush=True)
        for a in synced:
            request = mobilecoind_api_pb2.GetMonitorStatusRequest(monitor_id=a)
            monitor_block = stub.GetMonitorStatus(request).status.next_block
            if monitor_block == block_count:
                synced[a] = True
    return {a for a in synced if synced[a] == True}


def poll_mitosis(starting_balance, account_data, tx_stats, stub):
    complete = {t: False for t in tx_stats.keys()}
    pending = complete.keys()
    while not all(complete.values()):
        for tx_id in pending:
            try:
                resp = stub.GetBalance(
                    mobilecoind_api_pb2.GetBalanceRequest(
                        monitor_id=account_data.monitor_id
                    )
                )
                if (
                    resp.balance == starting_balance
                    and resp.account_block_height == resp.ledger_num_blocks
                ):
                    complete[tx_id] = True
                    tx_stats[tx_id]["time_delta"] = (
                        time.time() - tx_stats[tx_id]["start"]
                    )
                    tx_stats[tx_id]["block_delta"] = (
                        resp.ledger_num_blocks - tx_stats[tx_id]["block_start"]
                    )
                    # FIXME: don't know status currently...see below in poll
                    tx_stats[tx_id]["status"] = TransferStatus.success
            except Exception as exc:
                print(f"Got Balance exception: {repr(exc)}")
        pending = [k for k in complete if not complete[k]]
        print("Still pending:", len(pending))
        time.sleep(2)
    print("All accounts transfers complete")
    print(f"Stats: {tx_stats}")
    return tx_stats


def poll(monitor_id, tx_stats, stub):
    complete = {t: False for t in tx_stats.keys()}
    receipts = {t: tx_stats[t] for t in tx_stats.keys()}
    pending = complete.keys()
    while not all(complete.values()):
        for tx_id in pending:
            try:
                resp = stub.GetTxStatusAsSender(
                    mobilecoind_api_pb2.SubmitTxResponse(
                        sender_tx_receipt=receipts[tx_id]["receipt"].sender_tx_receipt,
                        receiver_tx_receipt_list=receipts[tx_id][
                            "receipt"
                        ].receiver_tx_receipt_list,
                    )
                )
                if resp.status == mobilecoind_api_pb2.TxStatus.TombstoneBlockExceeded:
                    print("Transfer did not complete in time", tx_id)
                    complete[tx_id] = True
                    tx_stats[tx_id]["time_delta"] = (
                        time.time() - tx_stats[tx_id]["start"]
                    )
                    tx_stats[tx_id]["status"] = TransferStatus.tombstoned
                elif resp.status == mobilecoind_api_pb2.TxStatus.Verified:
                    print("Transfer complete", tx_id)
                    complete[tx_id] = True
                    tx_stats[tx_id]["time_delta"] = (
                        time.time() - tx_stats[tx_id]["start"]
                    )
                    tx_stats[tx_id]["status"] = TransferStatus.success
                else:
                    print("Transfer status unknown", resp.status)
            except Exception as e:
                print(f"TransferStatus exception: {repr(e)}")
        pending = [k for k in complete if not complete[k]]
        time.sleep(0.25)
    print(f"All accounts transfers complete: Stats:\n {tx_stats}")
    return tx_stats
