import argparse
import subprocess

ROUTERS = ["r1", "r2", "r3", "r4"]
ROUTER_IDS = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
ROUTER_NETWORKS = [
    "10.0.2.0/24 10.0.3.0/24 10.0.14.0/24",
    "10.0.2.0/24 10.0.4.0/24",
    "10.0.4.0/24 10.0.5.0/24 10.0.15.0/24",
    "10.0.3.0/24 10.0.5.0/24"
]


def run(cmd):
    print(f"Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)


def build_topology():
    run("docker-compose up -d --build")


def start_ospf():
    for i, router in enumerate(ROUTERS):
        id = ROUTER_IDS[i]
        networks = ROUTER_NETWORKS[i]

        print(f"\n[+] Setting up {router}")
        run(f"docker exec {router} bash -c \"apt update && apt install -y curl gnupg lsb-release\"")
        run(f"docker exec {router} bash -c \"curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null\"")
        run(f"docker exec {router} bash -c \"echo 'deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) frr-stable' >> /etc/apt/sources.list.d/frr.list\"")
        run(f"docker exec {router} bash -c \"apt update && apt install -y frr frr-pythontools\"")
        run(f"docker exec {router} bash -c \"sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons\"")
        run(f"docker exec {router} service frr restart")

        # Configure OSPF
        ospf_commands = f"docker exec {router} vtysh -c 'configure terminal' -c 'router ospf' -c 'ospf router-id {id}'"
        for net in networks.split():
            ospf_commands += f" -c 'network {net} area 0.0.0.0'"
        ospf_commands += " -c 'exit' -c 'write memory'"
        run(ospf_commands)


def configure_hosts():
    print("\n[+] Configuring host routes")
    run("docker exec ha ip route add 10.0.15.0/24 via 10.0.14.4")
    run("docker exec hb ip route add 10.0.14.0/24 via 10.0.15.4")


def change_path(path):
    if path == "north":
        print("\n[+] Shifting traffic to north path (R1-R2-R3)")
        run("docker exec r1 vtysh -c 'conf t' -c 'interface eth2' -c 'ip ospf cost 10' -c 'exit' -c 'interface eth1' -c 'ip ospf cost 100' -c 'exit' -c 'write memory'")
    elif path == "south":
        print("\n[+] Shifting traffic to south path (R1-R4-R3)")
        run("docker exec r1 vtysh -c 'conf t' -c 'interface eth2' -c 'ip ospf cost 100' -c 'exit' -c 'interface eth1' -c 'ip ospf cost 10' -c 'exit' -c 'write memory'")
    else:
        print("Invalid path specified. Use 'north' or 'south'.")


def main():
    parser = argparse.ArgumentParser(description="Orchestrator to control Docker OSPF traffic routing.")
    parser.add_argument("--build-topology", action="store_true", help="Build the Docker network topology")
    parser.add_argument("--start-ospf", action="store_true", help="Install and configure FRR and OSPF")
    parser.add_argument("--configure-hosts", action="store_true", help="Configure routes on host containers")
    parser.add_argument("--path", choices=["north", "south"], help="Shift traffic to a given path")
    args = parser.parse_args()

    if args.build_topology:
        build_topology()
    if args.start_ospf:
        start_ospf()
    if args.configure_hosts:
        configure_hosts()
    if args.path:
        change_path(args.path)


if __name__ == "__main__":
    main()
