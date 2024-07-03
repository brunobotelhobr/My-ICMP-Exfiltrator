#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
# pip install termcolor
############################################################

from scapy.layers.inet import ICMP, IP
from scapy.all import conf
from scapy.all import sniff, Raw, sr1
from termcolor import colored
import datetime
import logging
import argparse
import os
import sys
import base64

# Disable scapy warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


NAME = "ICMP Ping Transfer"
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
        "-f",
        "--read-file",
        action="store",
        required=True,
        dest="read_file",
        help="[Required] File to send by ping.",
    )
    parser.add_argument(
        "-t",
        "--target",
        action="store",
        required=True,
        dest="target",
        help="[Required] Destinaation to send ICMP.",
    )
    return parser.parse_args()


def convert_bytes(num):
    """Convert bytes to KB, MB, GB, TB."""
    for x in ["bytes", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0


def file_size(args):
    """Return the file size."""
    if os.path.isfile(args.read_file):
        file_info = os.stat(args.read_file)
        return convert_bytes(file_info.st_size)


def pong_analyser(pkt, index):
    """ "Decode the payload and compare with the index."""
    if pkt is None:
        return False
    else:
        payload_base_64 = base64.b64decode(pkt[Raw].load)
        payload_string = payload_base_64.decode("utf-8")
        if payload_string == (index):
            return True
        else:
            return False


def main():
    """Main function."""
    setup()
    args = parse_arguments()
    print_banner()
    try:
        with open(args.read_file, "r", buffering=-1, encoding="utf-8") as file:
            file_data = file.read()
            print(log_timestamp() + " Destination: " + args.target)
            print(log_timestamp() + " File to Transfer: " + args.read_file)
            print(log_timestamp() + " File Size: " + file_size(args))  # type: ignore
            print(log_timestamp() + " File Characters: " + str(len(str(file_data))))
            print("")
            i = 0
            for c in file_data:
                i = i + 1
                index = str(str(i)).zfill(4) + "/" + str(len(file_data))
                ip = IP(dst=args.target)
                icmp = ICMP(type=8, code=0)
                index_c = c + "&&" + index
                raw_data = index_c.encode("utf-8")
                raw_encoded = base64.b64encode(raw_data)
                raw = Raw(load=raw_encoded)
                pkt = ip / icmp / raw
                confirmation = False
                printable_char = c
                if c.isprintable() is False:
                    printable_char = " "
                printable_payload = printable_char + "&&" + index
                print(
                    log_timestamp()
                    + " Transfering: "
                    + colored(index, "blue")
                    + " Payload > "
                    + printable_payload
                    + " Character > "
                    + colored(printable_char, "red")
                )
                while confirmation == False:
                    pck = sr1(pkt)
                    confirmation = pong_analyser(pck, index_c)
            file.close()
    except Exception as e:  # type: ignore
        print(f"Error reading file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
