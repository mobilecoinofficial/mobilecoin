#!/usr/bin/python3
# Copyright (c) 2018-2021 The MobileCoin Foundation

# TODO
# - Better errors on missing env vars
# - SGX HW/SW
# - Default MC_LOG
import argparse
import json
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import time
from pprint import pformat


BASE_CLIENT_PORT = 3200
BASE_PEER_PORT = 3300
BASE_ADMIN_PORT = 3400
BASE_ADMIN_HTTP_GATEWAY_PORT = 3500
MOBILECOIND_PORT = 4444

# TODO make these command line arguments
LEDGER_BASE = os.path.abspath(os.getenv("LEDGER_BASE"))
IAS_API_KEY = os.getenv("IAS_API_KEY")
IAS_SPID = os.getenv("IAS_SPID")
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MOB_RELEASE = os.getenv("MOB_RELEASE", "1")
CARGO_FLAGS = "--release"
TARGET_DIR = "target/release"
WORK_DIR = "/tmp/mc-local-network"
CLI_PORT = 31337

if MOB_RELEASE == "0":
    CARGO_FLAGS = ""
    TARGET_DIR = "target/debug"

# Sane default log configuration
if "MC_LOG" not in os.environ:
    os.environ[
        "MC_LOG"
    ] = "debug,rustls=warn,hyper=warn,tokio_reactor=warn,mio=warn,want=warn,rusoto_core=error,h2=error,reqwest=error,rocket=error,<unknown>=error"

# Cloud logging-sepcific configuration
LOG_BRANCH = os.getenv("LOG_BRANCH", None)
LOGSTASH_HOST = os.getenv("LOGSTASH_HOST", None)
GRAFANA_PASSWORD = os.getenv("GRAFANA_PASSWORD", None)


class CloudLogging:
    def __init__(self):
        self.filebeat_process = None
        self.prometheus_process = None

    def start(self, network):
        if not LOG_BRANCH:
            print(
                "No LOG_BRANCH environment variable - cloud logging would not be enabled."
            )
            return

        if LOGSTASH_HOST:
            self.start_filebeat(LOG_BRANCH, LOGSTASH_HOST)

        if GRAFANA_PASSWORD:
            hosts = ", ".join(
                f"'127.0.0.1:{BASE_ADMIN_HTTP_GATEWAY_PORT + i}'"
                for i in range(len(network.nodes))
            )
            self.start_prometheus(LOG_BRANCH, GRAFANA_PASSWORD, hosts)

    def start_filebeat(self, log_branch, logstash_host):
        print(f"Starting filebeat, branch={log_branch}")
        template = open(
            os.path.join(PROJECT_DIR, "tools", "local-network", "filebeat.yml.template")
        ).read()
        with open(os.path.join(WORK_DIR, "filebeat.yml"), "w") as f:
            f.write(
                template.replace("${BRANCH}", log_branch).replace(
                    "${LOGSTASH_HOST}", logstash_host
                )
            )
        os.chmod(os.path.join(WORK_DIR, "filebeat.yml"), 0o400)
        cmd = " ".join(
            [
                "filebeat",
                f"--path.config {WORK_DIR}",
                f"--path.data {WORK_DIR}/filebeat",
                f"--path.home {WORK_DIR}/filebeat",
                f"--path.logs {WORK_DIR}/filebeat",
            ]
        )
        print(f"  - {cmd}")
        self.filebeat_process = subprocess.Popen(cmd, shell=True)
        time.sleep(1)
        os.environ["MC_LOG_UDP_JSON"] = "127.0.0.1:16666"

    def start_prometheus(self, log_branch, grafana_password, hosts):
        print(f"Starting prometheus, branch={log_branch}")
        os.mkdir(os.path.join(WORK_DIR, "prometheus"))
        template = open(
            os.path.join(
                PROJECT_DIR, "tools", "local-network", "prometheus.yml.template"
            )
        ).read()
        with open(os.path.join(WORK_DIR, "prometheus.yml"), "w") as f:
            f.write(
                template.replace("${BRANCH}", log_branch)
                .replace("${GRAFANA_PASSWORD}", grafana_password)
                .replace("${HOSTS}", hosts)
            )
        cmd = " ".join(
            [
                "prometheus",
                "--web.listen-address=:18181",
                f"--config.file={WORK_DIR}/prometheus.yml",
                f"--storage.tsdb.path={WORK_DIR}/prometheus",
            ]
        )
        print(f"  - {cmd}")
        self.prometheus_process = subprocess.Popen(cmd, shell=True)
        time.sleep(1)


class QuorumSet:
    def __init__(self, threshold, members):
        self.threshold = threshold
        self.members = members

    def resolve_to_json(self, nodes_by_name):
        resolved_members = []
        for member in self.members:
            if isinstance(member, str):
                peer_port = nodes_by_name[member].peer_port
                resolved_members.append(
                    {"type": "Node", "args": f"localhost:{peer_port}"}
                )
            elif isinstance(member, QuorumSet):
                resolved_members.append(
                    {"type": "InnerSet", "args": member.resolve_to_json(nodes_by_name)}
                )
            else:
                raise Exception(f"Unsupported member type: {type(member)}")
        return {
            "threshold": self.threshold,
            "members": resolved_members,
        }


class Peer:
    def __init__(self, name, broadcast_consensus_msgs=True):
        self.name = name
        self.broadcast_consensus_msgs = broadcast_consensus_msgs

    def __repr__(self):
        return self.name


class Node:
    def __init__(
        self,
        name,
        node_num,
        client_port,
        peer_port,
        admin_port,
        admin_http_gateway_port,
        peers,
        quorum_set,
    ):
        assert all(isinstance(peer, Peer) for peer in peers)
        assert isinstance(quorum_set, QuorumSet)

        self.name = name
        self.node_num = node_num
        self.client_port = client_port
        self.peer_port = peer_port
        self.admin_port = admin_port
        self.admin_http_gateway_port = admin_http_gateway_port
        self.peers = peers
        self.quorum_set = quorum_set

        self.consensus_process = None
        self.ledger_distribution_process = None
        self.admin_http_gateway_process = None
        self.ledger_dir = os.path.join(WORK_DIR, f"node-ledger-{self.node_num}")
        self.ledger_distribution_dir = os.path.join(
            WORK_DIR, f"node-ledger-distribution-{self.node_num}"
        )
        self.msg_signer_key_file = os.path.join(
            WORK_DIR, f"node-scp-{self.node_num}.pem"
        )
        subprocess.check_output(
            f"openssl genpkey -algorithm ed25519 -out {self.msg_signer_key_file}",
            shell=True,
        )

    def peer_uri(self, broadcast_consensus_msgs=True):
        pub_key = (
            subprocess.check_output(
                f'openssl pkey -in {self.msg_signer_key_file} -pubout | head -n-1 | tail -n+2 | sed "s/+/-/g; s/\//_/g"',
                shell=True,
            )
            .decode()
            .strip()
        )
        broadcast_consensus_msgs = "1" if broadcast_consensus_msgs else "0"
        return f"insecure-mcp://localhost:{self.peer_port}/?consensus-msg-key={pub_key}&broadcast-consensus-msgs={broadcast_consensus_msgs}"

    def __repr__(self):
        return self.name

    def start(self, network):
        assert not self.consensus_process

        if self.ledger_distribution_process:
            self.ledger_distribution_process.terminate()
            self.ledger_distribution_process = None

        if self.admin_http_gateway_process:
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None

        # A map of node name -> Node object
        nodes_by_name = {node.name: node for node in network.nodes}

        # Private SCP signing key
        msg_signer_key = (
            subprocess.check_output(
                f"cat {self.msg_signer_key_file} | head -n-1 | tail -n+2", shell=True
            )
            .decode()
            .strip()
        )

        # URIs for the peers above
        peer_uris = [
            nodes_by_name[peer.name].peer_uri(
                broadcast_consensus_msgs=peer.broadcast_consensus_msgs,
            )
            for peer in self.peers
        ]

        # URIs for all additional nodes in the network, in case they appear in our quorum set
        peer_names = [peer.name for peer in self.peers]
        known_peers = [
            node.peer_uri()
            for node in network.nodes
            if node.name not in peer_names and node.name != self.name
        ]
        tx_source_urls = [
            f"file://{node.ledger_distribution_dir}"
            for node in network.nodes
            if node.name in peer_names
        ]

        # Our quorum set and associated JSON
        quorum_set = {
            "quorum_set": self.quorum_set.resolve_to_json(nodes_by_name),
            "broadcast_peers": peer_uris,
            "known_peers": known_peers,
            "tx_source_urls": tx_source_urls,
        }
        network_json_path = os.path.join(WORK_DIR, f"node{self.node_num}-network.json")
        with open(network_json_path, "w") as f:
            json.dump(quorum_set, f)

        try:
            shutil.rmtree(f"{WORK_DIR}/scp-debug-dump-{self.node_num}")
        except FileNotFoundError:
            pass

        cmd = " ".join(
            [
                f"cd {PROJECT_DIR} && exec {TARGET_DIR}/consensus-service",
                f"--client-responder-id localhost:{self.client_port}",
                f"--peer-responder-id localhost:{self.peer_port}",
                f'--msg-signer-key "{msg_signer_key}"',
                f"--network {network_json_path}",
                f"--ias-api-key={IAS_API_KEY}",
                f"--ias-spid={IAS_SPID}",
                f"--origin-block-path {LEDGER_BASE}",
                f"--ledger-path {self.ledger_dir}",
                f'--admin-listen-uri="insecure-mca://0.0.0.0:{self.admin_port}/"',
                f'--client-listen-uri="insecure-mc://0.0.0.0:{self.client_port}/"',
                f'--peer-listen-uri="insecure-mcp://0.0.0.0:{self.peer_port}/"',
                f"--scp-debug-dump {WORK_DIR}/scp-debug-dump-{self.node_num}",
                f"--sealed-block-signing-key {WORK_DIR}/consensus-sealed-block-signing-key-{self.node_num}",
            ]
        )

        print(
            f"Starting node {self.name}: client_port={self.client_port} peer_port={self.peer_port} admin_port={self.admin_port}"
        )
        print(f" - Peers: {self.peers}")
        print(f" - Quorum set: {pformat(quorum_set)}")
        print(cmd)
        print()

        self.consensus_process = subprocess.Popen(cmd, shell=True)

        # Wait for ledger db to become available
        ledger_db = os.path.join(self.ledger_dir, "data.mdb")
        while not os.path.exists(ledger_db):
            time.sleep(1)
            print(f"Waiting for {ledger_db}")

        cmd = " ".join(
            [
                f"cd {PROJECT_DIR} && exec {TARGET_DIR}/ledger-distribution",
                f"--ledger-path {self.ledger_dir}",
                f'--dest "file://{self.ledger_distribution_dir}"',
                f"--state-file {WORK_DIR}/ledger-distribution-state-{self.node_num}",
            ]
        )
        print(f"Starting local ledger distribution: {cmd}")
        self.ledger_distribution_process = subprocess.Popen(cmd, shell=True)

        cmd = " ".join(
            [
                f"cd {PROJECT_DIR} && export ROCKET_CLI_COLORS=0 && exec {TARGET_DIR}/mc-admin-http-gateway",
                f"--listen-host 0.0.0.0",
                f"--listen-port {self.admin_http_gateway_port}",
                f"--admin-uri insecure-mca://127.0.0.1:{self.admin_port}/",
            ]
        )
        print(f"Starting admin http gateway: {cmd}")
        self.admin_http_gateway_process = subprocess.Popen(cmd, shell=True)

    def status(self):
        if not self.consensus_process:
            return "stopped"

        if self.consensus_process.poll() is not None:
            return "exited"

        return f"running, pid={self.consensus_process.pid}"

    def stop(self):
        if self.consensus_process and self.consensus_process.poll() is None:
            self.consensus_process.terminate()
            self.consensus_process = None

        if (
            self.ledger_distribution_process
            and self.ledger_distribution_process.poll() is None
        ):
            self.ledger_distribution_process.terminate()
            self.ledger_distribution_process = None

        if (
            self.admin_http_gateway_process
            and self.admin_http_gateway_process.poll() is None
        ):
            self.admin_http_gateway_process.terminate()
            self.admin_http_gateway_process = None

        print(f"Stopped node {self}!")


class Mobilecoind:
    def __init__(self, client_port):
        self.client_port = client_port
        self.ledger_db = os.path.join(WORK_DIR, "mobilecoind-ledger-db")
        self.mobilecoind_db = os.path.join(WORK_DIR, "mobilecoind-db")
        self.watcher_db = os.path.join(WORK_DIR, "watcher-db")
        self.process = None

    def start(self, network):
        assert not self.process

        peers = [
            f'--peer "insecure-mc://localhost:{node.client_port}/"'
            for node in network.nodes
        ]
        tx_srcs = [
            f'--tx-source-url "file://{node.ledger_distribution_dir}"'
            for node in network.nodes
        ]

        cmd = " ".join(
            [
                f"cd {PROJECT_DIR} && exec {TARGET_DIR}/mobilecoind",
                f"--ledger-db {self.ledger_db}",
                f"--poll-interval 1",
                f"--mobilecoind-db {self.mobilecoind_db}",
                f"--listen-uri insecure-mobilecoind://0.0.0.0:{self.client_port}/",
                f"--watcher-db {self.watcher_db}",
            ]
            + peers
            + tx_srcs
        )

        print("Starting mobilecoind:", cmd)
        print()

        self.process = subprocess.Popen(cmd, shell=True)
        print()

        print("Waiting for watcher db to become available")
        while not os.path.exists(os.path.join(self.watcher_db, "data.mdb")):
            print("Waiting for watcher db to become available")
            time.sleep(1)

    def stop(self):
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
            self.process = None


class NetworkCLI(threading.Thread):
    """Network command line interface (over TCP)"""

    def __init__(self, network):
        super().__init__()
        self.network = network

    def run(self):
        network = self.network

        class NetworkCLITCPHandler(socketserver.StreamRequestHandler):
            def send(self, s):
                self.wfile.write(bytes(s, "utf-8"))

            def handle(self):
                self.send("> ")
                while True:
                    try:
                        line = self.rfile.readline().strip().decode()
                    except:
                        return

                    if not line:
                        continue

                    if " " in line:
                        cmd, args = line.split(" ", 1)
                    else:
                        cmd = line
                        args = ""

                    if cmd == "status":
                        for node in network.nodes:
                            self.send(f"{node.name}: {node.status()}\n")

                    elif cmd == "stop":
                        node = network.get_node(args)
                        if node:
                            node.stop()
                            self.send(f"Stopped {args}.\n")
                        else:
                            self.send(f"Unknown node {args}\n")

                    elif cmd == "start":
                        node = network.get_node(args)
                        if node:
                            node.stop()
                            node.start(network)
                            self.send(f"Started {args}.\n")
                        else:
                            self.send(f"Unknown node {args}\n")

                    else:
                        self.send("Unknown command\n")

                    self.send("> ")

        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.TCPServer(("0.0.0.0", CLI_PORT), NetworkCLITCPHandler)
        server.serve_forever()


class Network:
    def __init__(self):
        self.cloud_logging = None
        self.nodes = []
        self.ledger_distribution = None
        try:
            shutil.rmtree(WORK_DIR)
        except FileNotFoundError:
            pass
        os.mkdir(WORK_DIR)

    def build_binaries(self):
        print("Building binaries...")
        enclave_pem = os.path.join(PROJECT_DIR, "Enclave_private.pem")
        if not os.path.exists(enclave_pem):
            subprocess.run(
                f"openssl genrsa -out {enclave_pem} -3 3072",
                shell=True,
                check=True,
            )

        subprocess.run(
            f'cd {PROJECT_DIR} && CONSENSUS_ENCLAVE_PRIVKEY="{enclave_pem}" cargo build -p mc-consensus-service -p mc-ledger-distribution -p mc-admin-http-gateway -p mc-util-grpc-admin-tool {CARGO_FLAGS}',
            shell=True,
            check=True,
        )
        subprocess.run(
            f'cd {PROJECT_DIR} && CONSENSUS_ENCLAVE_PRIVKEY="{enclave_pem}" cargo build --no-default-features -p mc-mobilecoind {CARGO_FLAGS}',
            shell=True,
            check=True,
        )

    def add_node(self, name, peers, quorum_set):
        node_num = len(self.nodes)
        self.nodes.append(
            Node(
                name,
                node_num,
                BASE_CLIENT_PORT + node_num,
                BASE_PEER_PORT + node_num,
                BASE_ADMIN_PORT + node_num,
                BASE_ADMIN_HTTP_GATEWAY_PORT + node_num,
                peers,
                quorum_set,
            )
        )

    def get_node(self, name):
        for node in self.nodes:
            if node.name == name:
                return node

    def start(self):
        print("Killing any existing processes")
        try:
            subprocess.check_output(
                "killall -9 consensus-service filebeat ledger-distribution prometheus mc-admin-http-gateway mobilecoind 2>/dev/null",
                shell=True,
            )
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 1:
                raise

        self.cloud_logging = CloudLogging()
        self.cloud_logging.start(self)

        print("Starting nodes")
        for node in self.nodes:
            node.start(self)

        self.cli = NetworkCLI(self)
        self.cli.start()

        self.mobilecoind = Mobilecoind(MOBILECOIND_PORT)
        self.mobilecoind.start(self)

    def wait(self):
        """Block until one of our processes dies."""
        while True:
            for node in self.nodes:
                if node.consensus_process and node.consensus_process.poll() is not None:
                    print(
                        f"Node {node} consensus service died with exit code {node.consensus_process.poll()}"
                    )
                    return False

                if (
                    node.admin_http_gateway_process
                    and node.admin_http_gateway_process.poll() is not None
                ):
                    print(
                        f"Node {node} admin http gateway died with exit code {node.admin_http_gateway_process.poll()}"
                    )
                    return False

                if (
                    node.ledger_distribution_process
                    and node.ledger_distribution_process.poll() is not None
                ):
                    print(
                        f"Node {node} ledger distribution died with exit code {node.ledger_distribution_process.poll()}"
                    )
                    return False

            time.sleep(1)

    def default_entry_point(self, network_type, skip_build=False):
        if network_type == "dense5":
            #  5 node interconnected network requiring 4 out of 5  nodes.
            num_nodes = 5
            for i in range(num_nodes):
                other_nodes = [str(j) for j in range(num_nodes) if i != j]
                peers = [Peer(p) for p in other_nodes]
                self.add_node(str(i), peers, QuorumSet(3, other_nodes))

        elif network_type == "a-b-c":
            # 3 nodes, where all 3 are required but node `a` and `c` are not peered together.
            # (i.e. a <-> b <-> c)
            self.add_node("a", [Peer("b")], QuorumSet(2, ["b", "c"]))
            self.add_node("b", [Peer("a"), Peer("c")], QuorumSet(2, ["a", "c"]))
            self.add_node("c", [Peer("b")], QuorumSet(2, ["a", "b"]))

        elif network_type == "ring5":
            # A ring of 5 nodes where each node:
            # - sends SCP messages to the node before it and after it
            # - has the node after it in its quorum set
            self.add_node("1", [Peer("5"), Peer("2")], QuorumSet(1, ["2"]))
            self.add_node("2", [Peer("1"), Peer("3")], QuorumSet(1, ["3"]))
            self.add_node("3", [Peer("2"), Peer("4")], QuorumSet(1, ["4"]))
            self.add_node("4", [Peer("3"), Peer("5")], QuorumSet(1, ["5"]))
            self.add_node("5", [Peer("4"), Peer("1")], QuorumSet(1, ["1"]))

        elif network_type == "ring5b":
            # A ring of 5 nodes where each node:
            # - sends SCP messages to the node after it
            # - has the node after it in its quorum set
            self.add_node(
                "1",
                [Peer("5", broadcast_consensus_msgs=False), Peer("2")],
                QuorumSet(1, ["2"]),
            )
            self.add_node(
                "2",
                [Peer("1", broadcast_consensus_msgs=False), Peer("3")],
                QuorumSet(1, ["3"]),
            )
            self.add_node(
                "3",
                [Peer("2", broadcast_consensus_msgs=False), Peer("4")],
                QuorumSet(1, ["4"]),
            )
            self.add_node(
                "4",
                [Peer("3", broadcast_consensus_msgs=False), Peer("5")],
                QuorumSet(1, ["5"]),
            )
            self.add_node(
                "5",
                [Peer("4", broadcast_consensus_msgs=False), Peer("1")],
                QuorumSet(1, ["1"]),
            )

        else:
            raise Exception("Invalid network type")

        if not skip_build:
            self.build_binaries()

        self.start()
        self.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local network tester")
    parser.add_argument(
        "--network-type", help="Type of network to create", required=True
    )
    parser.add_argument(
        "--skip-build", help="Skip building binaries", action="store_true"
    )
    args = parser.parse_args()

    Network().default_entry_point(args.network_type, args.skip_build)
