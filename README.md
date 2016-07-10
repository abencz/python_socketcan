# Overview

This is a simple command line CAN utility that serves as an example of using
socketcan in Python 3. Requires at least Python 3.3.

# Usage

## Sending CAN Packets

    usage: python_socketcan_example.py send [-h] [-e] interface cob_id [body]

    positional arguments:
      interface          interface name (e.g. vcan0)
      cob_id             hexadecimal COB-ID (e.g. 10a)
      body               hexadecimal msg body up to 8 bytes long (e.g. 00af0142fe)

    optional arguments:
      -h, --help         show this help message and exit
      -e, --extended-id  use extended (29 bit) COB-ID

## Listening for CAN Packets

    usage: python_socketcan_example.py listen [-h] interface

    positional arguments:
      interface   interface name (e.g. vcan0)

    optional arguments:
      -h, --help  show this help message and exit
