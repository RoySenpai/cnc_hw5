# Communication and Computing Course Assigment 5
### For Computer Science B.Sc. Ariel University

**By Roy Simanovich and Yuval Yurzdichinsky**

## Description
* **Sniffer** – This program gets a command line argument to which network interface card attach to
and sniff all incoming and outcoming TCP packets. This program designed to sniff TCP packets from Ex2.
* **Spoofer** – This program gets a command line argument to which protocol the program will spoof
packets and then will continuously spoof packets.
* **Snooper** – The snooper program monitors the network, sniffs ICMP ECHO packets and spoofs fake 
ICMP ECHO REPLAY responses to the sending machine.
* **Gateway** – The gateway program listens to specific UDP port and for every packet sent to it,
it will decide with 50% chance what to do with it: send it forward to specific IP address (defined by the user)
or to drop the packet.

# Requirements
* Linux machine (Ubuntu 22.04 LTS recommanded)
* GNU C Compiler
* Make
* Libpcap (Packet Capture library)
* Docker
* Root privileges

## Building
```
# Cloning the repo to local machine
git clone https://github.com/RoySenpai/cnc_hw5.git

# Building all the necessary files & the main programs
make all
```

## Running
* **NOTE:** Before running the sniffer & snooper, please check your network interface card (NIC).
```
# Sniffing TCP packets from Ex2.
sudo ./Sniffer <device name> or sudo ./Sniffer

# Spoof some packets (ICMP, TCP & UDP).
sudo ./Spoofer <icmp or udp or tcp>

# Run the snooper program (ICMP ECHO packets only).
sudo ./Snoofer <device name> or ./Snoofer

# Run the gateway program (UDP packets only).
./Gateway <ip address>
```
