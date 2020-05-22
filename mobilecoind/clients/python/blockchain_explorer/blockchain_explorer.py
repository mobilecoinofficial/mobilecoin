# Copyright (c) 2018-2020 MobileCoin Inc.

import argparse
from flask import Flask, render_template
from sys import getsizeof

sys.path.append('../mob_client')
from mob_client import mob_client

client = mob_client('localhost:4444', False)
app = Flask(__name__)

def command_args():
    parser = argparse.ArgumentParser(description='MobileCoin Block Explorer')
    parser.add_argument('--port',
                        type=int,
                        required=False,
                        default=5000,
                        help='Block Explorer listen port')
    parser.add_argument('--mobilecoind_port',
                        type=int,
                        required=False,
                        default=4444,
                        help='Port of mobilecoind service to connect to')
    parser.add_argument('--mobilecoind_host',
                        type=str,
                        required=False,
                        default='localhost',
                        help='Hostname of mobilecoind service to connect to')
    return parser.parse_args()

def render_ledger_range(start, count):
    num_blocks, num_transactions = client.get_ledger_info()
    start = max(int(start), 0)
    finish = min(int(start + 100), num_blocks - 1)
    blocks = []
    signers = {}

    for i in range(finish, start, -1):
        key_image_count, txo_count = client.get_block_info(i)

        # very large blocks cause errors for client.get_block()
        # specifically ResourceExhausted for messages larger than 4194304
        # this is uniquely a problem for large origin blocks in testing
        # and should not appear in production
        if txo_count > 10000:
            continue

        block = client.get_block(i)
        block_row = (i,
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
    return render_template('index.html',
                           blocks=blocks,
                           num_blocks=num_blocks,
                           num_transactions=num_transactions,
                           signers=signers)


@app.route('/')
def index():
    num_blocks, num_transactions = client.get_ledger_info()
    return render_ledger_range(num_blocks - 101, 100)

@app.route('/<block_num>')
def page(block_num):
    num_blocks, num_transactions = client.get_ledger_info()
    block_num = int(block_num)
    return render_ledger_range(block_num, 100)

@app.route('/block/<block_num>')
def block(block_num):
    num_blocks, num_transactions = client.get_ledger_info()
    block_num = int(block_num)
    if block_num < 0 or block_num >= num_blocks:
        return render_template('block404.html',
                               block_num=block_num,
                               num_blocks=num_blocks)

    block = client.get_block(block_num)
    size_of_block = getsizeof(block)

    for signature in block.signatures:
        signature.src_url = signature.src_url.split('/')[-2]

    return render_template('block.html',
                           block_num=block_num,
                           block_hash=block.block.contents_hash.data,
                           key_image_count=len(block.key_images),
                           txo_count=len(block.txos),
                           txos=block.txos,
                           key_images=block.key_images,
                           size_of_block=size_of_block,
                           signatures=block.signatures)


if __name__ == "__main__":
    args = command_args()
    client = mob_client(
        args.mobilecoind_host + ':' + str(args.mobilecoind_port), False)
    app.run(host='0.0.0.0', port=str(args.port))
