# Scapy-Pipeline

Allows for the construction of Python programs which perform real-time
network traffic analysis, filtering, and modification through the
*Scapy* module.

Quickly build your IPv4 network filtering tool in a true UNIX
fashion - by using *pipes*.

## Notes

This tool currently only supports IPv4, not IPv6. Therefore it is
recommended that IPv6 be disabled.

```bash
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
```

## Installation

To use the library locally, simply run any of the below examples in the
cloned directory. To install this library system-wide, run
`sudo make install2.7` to install the library for Python 2.7 or
`sudo make install3` to install the library for Python 3.

## Examples

### pipe_program_ping.py (Use pipe_program_ping3.py for Python 3)

Generates an ICMP reply for any IPv4 address pinged.

```bash
mkfifo netpipe
cat netpipe | sudo socat -d -d STDIO TUN:192.168.10.1/24,up | python pipe_program_ping.py > netpipe
```

### pipe_program_ping_lossy.py (Use pipe_program_ping_lossy3.py for Python 3)

Same as pipe_program_ping.py but drops *one* in every *five* ICMP packets.

```bash
mkfifo netpipe
cat netpipe | sudo socat -d -d STDIO TUN:192.168.10.1/24,up | python pipe_program_ping_lossy.py > netpipe
```

### pipe_program_ping_inverted.py (Use pipe_program_ping_inverted3.py for Python 3)

Generates an ICMP reply for any IPv4 address pinged but with payload bits *inverted*.

```bash
mkfifo netpipe
cat netpipe | sudo socat -d -d STDIO TUN:192.168.10.1/24,up | python pipe_program_ping_inverted.py > netpipe
```

### Filtering Network Traffic From A Different Network Namespace

Enter a **new** *network namespace* and get a PID within this namespace.

```bash
unshare -n -r
pidof /bin/bash

#We will assume the returned PID was 8989
```

In the **original** *network namespace* create the *tun0* and *tun1* interfaces.

```bash
mkfifo netpipe
cat netpipe | sudo socat -d -d STDIO TUN:192.168.10.1/24,up | sudo socat -d -d STDIO TUN:192.168.10.2/24,up | python pipe_program_passthrough.py > netpipe
```

Move the *tun1* interface to the **new** *network namespace*.

```bash
#Once again assuming the PID 8989 is within this namespace
ip link set tun1 netns 8989
```

Within the **new** *network namespace* execute the command:

```bash
ifconfig tun1 192.168.10.2/24
```

Allow traffic from *tun0* to be forwarded to the Internet.

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -I POSTROUTING -s 192.168.10.2 -o eth0 -j MASQUERADE
```

In the **new** *network namespace* generate traffic to be passed over
the *scapy-pipeline* to the Internet.

```bash
route add default gw 192.168.10.1
python
>>> import requests
>>> r = requests.get("https://icanhazip.com")
>>> print r.text
```

The network traffic moving from client to server will be filtered and
displayed according to the logic defined in `pipe_program_passthrough.py`.


### Transporting IPv4 Traffic Over A Covert ICMP Channel

- Install my [ICMPcat](https://github.com/IntegralProgrammer/ICMPcat) utility.

On the server:

```bash
sudo sysctl net.ipv4.icmp_echo_ignore_all=1
mkfifo netpipe
cat netpipe | sudo socat -d -d STDIO TUN:192.168.10.1/24,up | python socat2b64line.py | sudo python icmpcat_server.py | python b64line2socat.py > netpipe
```

On the client:

```bash
mkfifo netpipe
cat netpipe | sudo socat -d -d STDIO TUN:192.168.10.2/24,up | python socat2b64line.py | sudo python icmpcat_client.py <PUBLIC IP OF SERVER> 0.01 | python b64line2socat.py > netpipe
```

The *client* **192.168.10.2** should now be able to access network services on the *server* **192.168.10.1**.
