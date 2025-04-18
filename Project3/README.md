# Running OSPF topology
1. create a powder vnc by going to https://www.powderwireless.net/p/CS4480-2025/shared-vm-vnc-non-routable-ip and creating an enviorment
2. once in the enviorment `git clone https://gitlab.flux.utah.edu/teach-studentview/cs4480-2025-s.git`
3. next `git clone https://github.com/emma-luky/4480ComputerNetworks.git`
4. `cd cs4480-2025-s/pa3/part1`
5. `cp ../../../4480ComputerNetworks/Project3/setup_frr.sh setup_frr.sh`
6. `cp ../../../4480ComputerNetworks/Project3/orchestrator.py orchestrator.py`
7. `cp -f ../../../4480ComputerNetworks/Project3/docker-compose.yaml docker-compose.yaml`
NOTE: run python3 orchestrator.py -h to see all options
8. `python3 orchestrator.py --build-topology`
9. `python3 orchestrator.py --build-containers`
10. `python3 orchestrator.py --start-ospf`
11. `python3 orchestrator.py --configure-hosts`
Your docker containers are now all set up and running and ready for testing.
