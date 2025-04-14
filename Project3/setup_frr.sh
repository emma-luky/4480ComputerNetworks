#!/bin/bash

# Define the router container names
ROUTERS=("r1" "r2" "r3" "r4")

# Function to install FRR on a router
install_frr() {
    local router=$1
    echo "Setting up FRR on $router..."
    
    # Connect to the router container and run commands
    docker exec $router bash -c '
        # Update and install prerequisites
        apt -y update
        apt -y install curl gnupg lsb-release
        
        # Add FRR repository keys
        curl -s https://deb.frrouting.org/frr/keys.gpg | tee /usr/share/keyrings/frrouting.gpg > /dev/null
        
        # Add FRR repository
        FRRVER="frr-stable"
        echo deb "[signed-by=/usr/share/keyrings/frrouting.gpg]" https://deb.frrouting.org/frr $(lsb_release -s -c) $FRRVER | tee -a /etc/apt/sources.list.d/frr.list
        
        # Install FRR
        apt update && apt -y install frr frr-pythontools
        
        # Enable OSPF daemon
        sed -i "s/ospfd=no/ospfd=yes/g" /etc/frr/daemons
        
        # Restart FRR service
        service frr restart
        
        # Verify OSPF is running
        echo "Verifying OSPF daemon on $HOSTNAME:"
        ps -ef | grep ospf
    '
    
    echo "FRR setup completed on $router"
    echo "----------------------------------------"
}

# Main script execution
echo "Starting FRR setup on all routers..."

# Check if containers are running
for router in "${ROUTERS[@]}"; do
    if ! docker ps | grep -q "$router"; then
        echo "Error: Container $router is not running!"
        echo "Please start your Docker containers first with 'docker-compose up -d'"
        exit 1
    fi
done

# Install FRR on each router
for router in "${ROUTERS[@]}"; do
    install_frr $router
done

echo "FRR setup completed on all routers!"
echo "You can now configure OSPF on each router using 'vtysh'"
