# Overview
The primary goal of this assignment is to become familiar with software defined networking (SDN) concepts
by developing a simple OpenFlow application using the POX SDN framework 1. Your SDN application will
realize a simple “virtual IP load balancing switch”. (I.e., a switch that will map, in round-robin fashion, a
virtual IP address to a set of real IP addresses associated with servers “behind” it.) You will make use of two
testbed environments for this assignment. First, you will be using a virtual networking environment called
Mininet2. Mininet allows the emulation of arbitrary network topologies inside a single physical or virtual
machine. Of specific interest for our purposes is the fact that Mininet can instantiate OpenFlow capable
switches in this emulated environment. Second, to simplify the task of setting up Mininet, we will make
use of the POWDER testbed environment3. Specifically, we have created a virtual machine (VM) profile in
POWDER, which you can instantiate to install the Mininet environment and the POX framework. Each
student can use this profile to easily instantiated (their own) VM for the assignment