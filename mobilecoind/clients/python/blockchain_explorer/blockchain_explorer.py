#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2018-2021 The MobileCoin Foundation

import argparse, datetime
from flask import Flask, render_template

import os, sys
import mobilecoin

client = None  # client is initialized at the bottom of this file
app = Flask(__name__)


def command_args():
    parser = argparse.ArgumentParser(description="MobileCoin Block Explorer")
    parser.add_argument(
        "--port",
        type=int,
        required=False,
        default=5000,
        help="Block Explorer listen port",
    )
    parser.add_argument(
        "--mobilecoind_port",
        type=int,
        required=False,
        default=4444,
        help="Port of mobilecoind service to connect to",
    )
    parser.add_argument(
        "--mobilecoind_host",
        type=str,
        required=False,
        default="localhost",
        help="Hostname of mobilecoind service to connect to",
    )
    return parser.parse_args()


def render_ledger_range(start, count):
    ledger_info_response = client.get_ledger_info()
    num_blocks = ledger_info_response.block_count
    num_transactions = ledger_info_response.txo_count

    start = max(int(start), 0)
    finish = min(int(start + 100), num_blocks - 1)
    if finish - start < 100:
        start = max(0, finish - 100)

    blocks = []
    signers = {}

    for i in range(finish, start, -1):
        block_info_response = client.get_block_info(i)
        key_image_count = block_info_response.key_image_count
        txo_count = block_info_response.txo_count

        # very large blocks cause errors for client.get_block()
        # specifically ResourceExhausted for messages larger than 4194304
        # this is uniquely a problem for large origin blocks in testing
        # and should not appear in production
        if txo_count > 10000:
            continue

        block = client.get_block(i)
        block_row = (
            i,
            bytes.hex(block.block.contents_hash.data),
            txo_count,
            key_image_count,
            len(block.signatures),
        )
        blocks.append(block_row)

        # Process signature data - sort by signer
        for signature_data in block.signatures:
            signature = signature_data.signature.signature
            signer = bytes.hex(signature_data.signature.signer.data)
            # If a new signer has appeared, prepend False for all previous blocks
            if signer not in signers:
                signers[signer] = [False for i in range(i - 1)]
            signers[signer].append(True)
    return render_template(
        "index.html",
        start=start,
        finish=finish,
        blocks=blocks,
        num_blocks=num_blocks,
        num_transactions=num_transactions,
        signers=signers,
    )


@app.template_filter("datetime")
def format_datetime(value):
    if not value:
        return "N/A"
    return datetime.datetime.fromtimestamp(value).isoformat()


@app.route("/")
def index():
    ledger_info_response = client.get_ledger_info()
    num_blocks = ledger_info_response.block_count
    num_transactions = ledger_info_response.txo_count
    return render_ledger_range(num_blocks - 101, 100)


@app.route("/from/<block_num>")
def ledger(block_num):
    return render_ledger_range(int(block_num), 100)


@app.route("/block/<block_num>")
def block(block_num):
    ledger_info_response = client.get_ledger_info()
    num_blocks = ledger_info_response.block_count
    num_transactions = ledger_info_response.txo_count
    block_num = int(block_num)
    if block_num < 0 or block_num >= num_blocks:
        return render_template(
            "block404.html", block_num=block_num, num_blocks=num_blocks
        )

    block = client.get_block(block_num)
    size_of_block = sys.getsizeof(block)

    for signature in block.signatures:
        signature.src_url = signature.src_url.split("/")[-2]

    return render_template(
        "block.html",
        block_num=block_num,
        block_hash=block.block.contents_hash.data,
        key_image_count=len(block.key_images),
        txo_count=len(block.txos),
        txos=block.txos,
        key_images=block.key_images,
        size_of_block=size_of_block,
        signatures=block.signatures,
    )


if __name__ == "__main__":
    args = command_args()
    client = mobilecoin.Client(
        args.mobilecoind_host + ":" + str(args.mobilecoind_port), False
    )
    app.run(host="0.0.0.0", port=str(args.port))
