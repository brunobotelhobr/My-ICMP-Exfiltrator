#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
# pip install termcolor
############################################################

from scapy.layers.inet import ICMP, IP
from scapy.all import conf
from scapy.all import sniff, Raw, sr1, send
from termcolor import colored
import datetime
import logging
import argparse
import os
import sys
import base64

# Disable scapy warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


NAME = "ICMP Pong Transfer"
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


def parse_arguments():
    """Parse and return arguments from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-w",
        "--write-file",
        action="store",
        required=True,
        dest="output_file",
        help="[Required] File to write output.",
    )
    return parser.parse_args()


def ack_icmp(ip_dst, index):
    """Send an ICMP packet with the ACK."""
    ip = IP(src=ip_dst)
    icmp = ICMP(type=0, code=0)
    index_c = "OK" + index
    index_c = index_c.encode("utf-8")
    index_c = base64.b64encode(index_c)
    raw = Raw(index_c)
    pkt = ip / icmp / raw
    send(pkt)


def icmp_process(pkt):
    """Process the ICMP packet."""
    if ICMP in pkt and pkt[ICMP].type == 8:
        try:
            file = parse_arguments().output_file
            payload_base_64 = base64.b64decode(pkt[Raw].load)
            payload_string = payload_base_64.decode("utf-8")
            payload_vetor = payload_string.split("&&")
            if len(payload_vetor) == 2:
                print(
                    log_timestamp()
                    + " Writing to "
                    + colored(file, "green")
                    + " Index > "
                    + colored(payload_vetor[1], "blue")
                    + " Character > "
                    + colored(payload_vetor[0].rstrip("\n"), "red")
                )
                file = open(file, "a", encoding="utf-8")
                ack_icmp(pkt[IP].src, payload_string)
                file.write(payload_vetor[0])
                file.close()
                fim = payload_vetor[1].split("/")
                if fim[0] == fim[1]:
                    exit()
        except Exception as e:
            print(log_timestamp(), "Packet not Parseable")


def icmp_mon():
    """Monitor the ICMP packets."""
    sniff(prn=icmp_process, store=0, filter="icmp")


def main():
    """Main function."""
    setup()
    args = parse_arguments()
    print_banner()
    print("###[ " + log_timestamp() + " Starting ICMP Monitoring ")
    print("###[ " + log_timestamp() + " File to Write: " + args.output_file)
    print("")
    try:
        with open(args.read_file, "r", buffering=-1, encoding="utf-8") as file:
            file.close()
    except Exception as e:  # type: ignore
        # Create the file if it does not exist
        print("###[ " + log_timestamp() + " Creating file: " + args.output_file)
        file = open(args.output_file, "w", encoding="utf-8")
        file.close()
    icmp_mon()


if __name__ == "__main__":
    main()
