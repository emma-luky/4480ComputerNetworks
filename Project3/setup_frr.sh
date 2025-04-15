#!/bin/bash

# Define router names and OSPF router-IDs
ROUTERS=("part1-r1-1" "part1-r2-1" "part1-r3-1" "part1-r4-1")
ROUTER_IDS=("1.1.1.1" "2.2.2.2" "3.3.3.3" "4.4.4.4")

# Define networks each router should advertise (example: adjust for your topology)
ROUTER_NETWORKS=(
  "10.0.2.0/24 10.0.3.0/24 10.0.14.0/24"   # R1
  "10.0.2.0/24 10.0.4.0/24"                # R2
  "10.0.4.0/24 10.0.5.0/24 10.0.15.0/24"   # R3
  "10.0.3.0/24 10.0.5.0/24"                # R4
)

install_frr_and_configure_ospf() {
    local router=$1
    local id=$2
    local networks=$3

    echo "Setting up FRR and OSPF on $router..."

    docker exec $router bash -c "
        apt -y update
        apt -y install curl gnupg lsb-release

        curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null
        FRRVER='frr-stable'
        echo deb '[signed-by=/usr/share/keyrings/frrouting.gpg]' https://deb.frrouting.org/frr \$(lsb_release -s -c) \$FRRVER | tee -a /etc/apt/sources.list.d/frr.list

        apt update && apt -y install frr frr-pythontools
        sed -i 's/ospfd=no/ospfd=yes/g' /etc/frr/daemons
        service frr restart
    "

    # Construct vtysh command as a multiline string
    VTYSH_COMMAND="configure terminal
router ospf
ospf router-id $id"

    for net in $networks; do
        VTYSH_COMMAND+="
network $net area 0.0.0.0"
    done

    VTYSH_COMMAND+="
exit
write memory"

    echo "Configuring OSPF on $router..."
    docker exec -i $router vtysh <<< "$VTYSH_COMMAND"

    echo "FRR and OSPF setup complete for $router."
    echo "----------------------------------------"
}

# Run setup for each router
for i in "${!ROUTERS[@]}"; do
    install_frr_and_configure_ospf "${ROUTERS[$i]}" "${ROUTER_IDS[$i]}" "${ROUTER_NETWORKS[$i]}"
done
