#!/usr/bin/env python3

# This is an integration test that downloads the latest releases and attempts to run mobilecoind,
# the mirror services and the JSON gateway in the exact manner that a user might run them, using the
# provided shell scripts and compiled binaries.

import argparse
import os
import requests
import signal
import subprocess
import sys
import tarfile
import time

parser = argparse.ArgumentParser(
    description="Download and test mobilecoind / mirror and json gateway"
)
parser.add_argument(
    "entropy", metavar="e", type=str, help="Root entropy of account for testing"
)
parser.add_argument(
    "--url",
    metavar="u",
    type=str,
    help="URL of release tarball",
    default="https://github.com/mobilecoinfoundation/mobilecoin/releases/latest/download/mobilecoind-mirror-tls.tar.gz",
)
parser.add_argument(
    "--skip-clean",
    action="store_true",
    help="Do not delete ledger-db and mobilecoind-db on start",
)
parser.add_argument(
    "--services",
    action="store_true",
    help="Leave services up after test run is complete",
)
args = parser.parse_args()

target_path = "mobilecoind-mirror-tls.tar.gz"

if not args.skip_clean:
    # Cleanup any previous runs and re-sync the ledger.
    subprocess.run("rm -r /tmp/mobilecoin", shell=True)
subprocess.run("pkill -f mobilecoind", shell=True)

os.chdir("/tmp")

# Download the release
response = requests.get(args.url, stream=True)
if response.status_code == 200:
    with open(target_path, "wb") as f:
        f.write(response.raw.read())
else:
    print("Failed to download latest tarball")
    sys.exit(1)

# Extract it
tar = tarfile.open(target_path)
tar.extractall()
tar.close()

os.chdir("/tmp/mobilecoind-mirror")

# Launch both sides of the mirror and the mobilecoind test
public_process = subprocess.Popen(
    "./mobilecoind-mirror-public.sh", shell=True, preexec_fn=os.setsid
)
private_process = subprocess.Popen(
    "echo %s |./mobilecoind-mirror-private.sh localhost:10080" % (args.entropy),
    shell=True,
    preexec_fn=os.setsid,
)
json_process = subprocess.Popen(
    "bin/mobilecoind-json", shell=True, preexec_fn=os.setsid
)


def shutdown(exit_code):
    # Shut down all the process groups
    os.killpg(os.getpgid(public_process.pid), signal.SIGTERM)
    os.killpg(os.getpgid(private_process.pid), signal.SIGTERM)
    os.killpg(os.getpgid(json_process.pid), signal.SIGTERM)
    sys.exit(exit_code)


# Give everything a chance to start up
print("Waiting for startup of all services")
time.sleep(10)

# Check the block API
print("Testing mirror block API")
response = requests.get("http://localhost:8001/ledger/blocks/0")
if response.status_code == 200:
    data = response.json()
    if data["index"] != "0":
        print("Block API returned invalid data")
        shutdown(1)
    print("Block API call succeeded")
else:
    print("Block API returned status code %d" % response.status_code)
    shutdown(1)

# Get ledger status, poll until caught up
last_block = 0
print("Downloading ledger blocks")
while True:
    response = requests.get("http://localhost:9090/ledger/local")
    if response.status_code == 200:
        block_count = int(response.json()["block_count"])
        print("Blocks downloaded = %d" % block_count)
        if block_count == last_block:
            break
        last_block = block_count
        time.sleep(5)
    else:
        print("Ledger local endpoint returned status code %d" % response.status_code)
        shutdown(1)

# Get the account key for the provided entropy
response = requests.get("http://localhost:9090/entropy/%s" % args.entropy)
if response.status_code == 200:
    account_key = response.json()
    print("Account key = %s" % str(account_key))
else:
    print("Account key endpoint returned status code %d" % response.status_code)
    shutdown(1)

# Get the monitor for the account
monitor_data = {
    "account_key": account_key,
    "first_subaddress": 0,
    "num_subaddresses": 1000,
}
response = requests.post("http://localhost:9090/monitors", json=monitor_data)
if response.status_code == 200:
    monitor_id = response.json()["monitor_id"]
    print("Monitor id = %s" % monitor_id)
else:
    print("Monitor endpoint returned status code %d" % response.status_code)
    shutdown(1)

# Get the public address for the monitor and subaddress
response = requests.get(
    "http://localhost:9090/monitors/%s/subaddresses/0/public-address" % monitor_id
)
if response.status_code == 200:
    public_address = response.json()
    print("Public address = %s" % str(public_address))
    b58_address_code = response.json()["b58_address_code"]
else:
    print("Public address endpoint returned status code %d" % response.status_code)
    shutdown(1)

# Generate a request code for the account
request_data = {"receiver": public_address, "value": "1", "memo": "Please pay me"}
response = requests.post("http://localhost:9090/codes/request", json=request_data)
if response.status_code == 200:
    request_code = response.json()["b58_request_code"]
    print("Request code = %s" % str(request_code))
else:
    print("Request code endpoint returned status code %d" % response.status_code)
    shutdown(1)

# Loop until monitor is synced
while True:
    response = requests.get("http://localhost:9090/monitors/%s" % monitor_id)
    if response.status_code == 200:
        next_block = int(response.json()["next_block"])
        print("Monitor next block = %d" % next_block)
    else:
        print("Monitor status returned status code %d" % response.status_code)
        shutdown(1)
    if next_block >= block_count:
        break
    time.sleep(1)

time.sleep(2)

# Do a balance check
url = "http://localhost:9090/monitors/%s/subaddresses/0/balance" % monitor_id
response = requests.get(url)
if response.status_code == 200:
    balance = int(response.json()["balance"])
    print("balance = %d" % balance)
else:
    print("Ledger local endpoint returned status code %d" % response.status_code)
    shutdown(1)

# Testing transfers requires the account to have a positive balance
if balance == 0:
    print("Cannot continue testing with a non-funded account")
    shutdown(1)

# Initiate a transfer, to the same account
url = "http://localhost:9090/monitors/%s/subaddresses/0/build-and-submit" % monitor_id
payment_data = {
    "request_data": {"receiver": public_address, "value": "1", "memo": "Please pay me"}
}
response = requests.post(url, json=payment_data)
if response.status_code == 200:
    receipts = response.json()
    receiver_tx_receipt = response.json()["receiver_tx_receipt_list"][0]
else:
    print("build-and-submit returned status code %d" % response.status_code)
    shutdown(1)

print("Polling for transaction status")
while True:
    response = requests.post("http://localhost:9090/tx/status-as-sender", json=receipts)
    if response.status_code == 200:
        status = response.json()["status"]
        print("status = %s" % status)
        if status == "verified":
            break
        time.sleep(1)
    else:
        print("status-as-sender returned status code %d" % response.status_code)
        shutdown(1)

# Monitor must update to avoid a double-spend
time.sleep(10)

# Test pay address code also with an alternate change subaddress
url = "http://localhost:9090/monitors/%s/subaddresses/0/pay-address-code" % monitor_id
payment_data = {
    "receiver_b58_address_code": b58_address_code,
    "value": "1",
    "change_subaddress": "2",
}
response = requests.post(url, json=payment_data)
if response.status_code == 200:
    receipts = response.json()
    receiver_tx_receipt = response.json()["receiver_tx_receipt_list"][0]
else:
    print("pay-address-code returned status code %d" % response.status_code)
    shutdown(1)

print("Polling for transaction status")
while True:
    response = requests.post("http://localhost:9090/tx/status-as-sender", json=receipts)
    if response.status_code == 200:
        status = response.json()["status"]
        print("status = %s" % status)
        if status == "verified":
            break
        time.sleep(1)
    else:
        print("status-as-sender returned status code %d" % response.status_code)
        shutdown(1)

print("Testing mirror block API")
response = requests.get("http://localhost:8001/ledger/blocks/0")
if response.status_code == 200:
    data = response.json()
    if data["index"] != "0":
        print("Block API returned invalid data")
        shutdown(1)
    print("Block API call succeeded")
else:
    print("Block API returned status code %d" % response.status_code)
    shutdown(1)

# Check the mirror to see the block height of the transaction
tx_pubkey = receiver_tx_receipt["tx_public_key"]
url = f"http://localhost:8001/tx-out/{tx_pubkey}/block-index"
response = requests.get(url)
if response.status_code == 200:
    block_index = response.json()["block_index"]
    print(f"Got block_index = {block_index}")
else:
    print(
        "tx-out/tx_public_key/block-index returned status code %d"
        % response.status_code
    )
    shutdown(1)

# Allow block to get processed
time.sleep(5)

# Get the processed block for that block index
url = f"http://localhost:8001/processed-block/{block_index}"
response = requests.get(url)
if response.status_code == 200:
    processed_block_pub = response.json()
    print(f"Got processed_block = {processed_block_pub}")
else:
    print("processed-block/block-index returned status code %d" % response.status_code)
    shutdown(1)

# Get the processed block for that block index via mobilecoind-json
url = f"http://localhost:9090/monitors/{monitor_id}/processed-block/{block_index}"
response = requests.get(url)
if response.status_code == 200:
    processed_block = response.json()
    print(f"Got processed_block = {processed_block}")
    assert processed_block == processed_block_pub, "Processed blocks do not match"
else:
    print(
        "monitors/monitor-id/processed-block/block-index returned status code %d"
        % response.status_code
    )
    shutdown(1)

time.sleep(10)

# Now do the reverse to make sure the original subaddress is still funded
url = "http://localhost:9090/monitors/%s/subaddresses/2/pay-address-code" % monitor_id
payment_data = {
    "receiver_b58_address_code": b58_address_code,
    "value": "1",
    "change_subaddress": "0",
}
response = requests.post(url, json=payment_data)
if response.status_code == 200:
    receipts = response.json()
    receiver_tx_receipt = response.json()["receiver_tx_receipt_list"][0]
else:
    print("pay-address-code returned status code %d" % response.status_code)
    shutdown(1)

print("Polling for transaction status")
while True:
    response = requests.post("http://localhost:9090/tx/status-as-sender", json=receipts)
    if response.status_code == 200:
        status = response.json()["status"]
        print("status = %s" % status)
        if status == "verified":
            break
        time.sleep(1)
    else:
        print("status-as-sender returned status code %d" % response.status_code)
        shutdown(1)

print("Testing mirror block API")
response = requests.get("http://localhost:8001/ledger/blocks/0")
if response.status_code == 200:
    data = response.json()
    if data["index"] != "0":
        print("Block API returned invalid data")
        shutdown(1)
    print("Block API call succeeded")
else:
    print("Block API returned status code %d" % response.status_code)
    shutdown(1)

# Check the mirror to see the block height of the transaction
tx_pubkey = receiver_tx_receipt["tx_public_key"]
url = f"http://localhost:8001/tx-out/{tx_pubkey}/block-index"
response = requests.get(url)
if response.status_code == 200:
    block_index = response.json()["block_index"]
    print(f"Got block_index = {block_index}")
else:
    print(
        "tx-out/tx_public_key/block-index returned status code %d"
        % response.status_code
    )
    shutdown(1)

# Allow block to get processed
time.sleep(5)

# Get the processed block for that block index
url = f"http://localhost:8001/processed-block/{block_index}"
response = requests.get(url)
if response.status_code == 200:
    processed_block_pub = response.json()
    print(f"Got processed_block = {processed_block_pub}")
else:
    print("processed-block/block-index returned status code %d" % response.status_code)
    shutdown(1)

# Get the processed block for that block index via mobilecoind-json
url = f"http://localhost:9090/monitors/{monitor_id}/processed-block/{block_index}"
response = requests.get(url)
if response.status_code == 200:
    processed_block = response.json()
    print(f"Got processed_block = {processed_block}")
    assert processed_block == processed_block_pub, "Processed blocks do not match"
else:
    print(
        "monitors/monitor-id/processed-block/block-index returned status code %d"
        % response.status_code
    )
    shutdown(1)

print("All tests succeeded!")

if args.services:
    # Leave services up for local testing
    sys.exit(0)
else:
    shutdown(0)
