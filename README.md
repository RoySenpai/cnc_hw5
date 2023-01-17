# Communication and Computing Course Assigment 5
### For Computer Science B.Sc. Ariel University

**By Roy Simanovich and Yuval Yurzdichinsky**

## Description


# Requirements
* Linux machine
* GNU C Compiler
* Make
* Docker

## Building
```
# Cloning the repo to local machine
git clone https://github.com/RoySenpai/cnc_hw5.git

# Building all the necessary files & the main programs
make all
```

## Running
* **NOTE:** Before running the sniffer & snooper, please change the network interface.
```
# Sniffing TCP packets from Ex2.
sudo ./Sniffer

# Spoof some packets (ICMP, TCP & UDP).
sudo ./Spoofer

# Run the snooper program (ICMP ECHO packets only).
sudo ./Snooper

# Run the gateway program (UDP packets only).
./Gateway
```
