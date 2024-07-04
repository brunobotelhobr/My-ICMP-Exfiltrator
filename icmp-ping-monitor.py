#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
# pip install termcolor
############################################################

from scapy.layers.inet import ICMP, IP
from scapy.all import conf
from scapy.all import sniff
from termcolor import colored
import datetime
import logging

# Disable scapy warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


NAME = "Ping Payload Monitor"
VERSION = "1.0"
DATE = "02/06/2024"
IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"


def print_banner():
    """Print the banner."""
    print("")
    print(f"### {NAME}")
    print(f"### Version {VERSION}")
    print(f"### Date {DATE}")
    print("### by Bruno Botelho - bruno.botelho.br@gmail.com")
    print("")


def setup():
    """Setup the environment based on provided arguments."""
    conf.verb = 0  # Disable default scapy output


def log_timestamp():
    """Return the current timestamp."""
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def icml_mon(pkt):
    """Monitor ICMP packets."""
    if pkt.haslayer(ICMP) and pkt.getlayer(ICMP):
        icmp_suspicious = pkt[ICMP].load
        if len(icmp_suspicious) == 56 or len(icmp_suspicious) == 32:
            print(
                log_timestamp()
                + " Normal payload with size "
                + colored(str(len(icmp_suspicious)), "green")
            )
        else:
            src = pkt[IP].src
            size = len(icmp_suspicious)
            payload = icmp_suspicious
            print(
                log_timestamp()
                + " Suspicious payload from"
                + colored(src, "red")
                + " with size "
                + colored(size, "red")
                + " found as: "
                + colored(payload, "red")
            )


def main():
    """Main function."""
    setup()
    print_banner()
    try:
        while True:
            sniff(prn=icml_mon)
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)


if __name__ == "__main__":
    main()
