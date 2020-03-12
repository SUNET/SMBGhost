#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import struct
import ipaddress
from multiprocessing.dummy import Pool as ThreadPool

def smbghost_check(host):
    pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
    try:
        with socket.socket(socket.AF_INET) as sock:
            sock.settimeout(3)
            sock.connect(( str(host),  445 ))
            sock.send(pkt)

            nb, = struct.unpack(">I", sock.recv(4))
            res = sock.recv(nb)
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None

    if not res[68:70] == b"\x11\x03":
        return None
    if not res[70:72] == b"\x02\x00":
        return None

    return host

def main():
    if len(sys.argv) < 2:
        print('Usage: ./scanner.py text-file-with-subnets')
        sys.exit(1)

    # This is actually quite low since the timeout for each
    # check is set to 3s and even on a low end VM the load
    # was hardy noticeble.
    scan_pool = ThreadPool(500)

    with open(sys.argv[1]) as f:
        for line in f:
            network_to_check = line.rstrip('\n')

            hosts_to_scan = ipaddress.ip_network(network_to_check).hosts()
            scan_result = scan_pool.map(smbghost_check, hosts_to_scan)
            try:
                scan_pool.join()
                scan_pool.close()
            except:
                pass

            # Filter the result to only include vulnerable hosts
            hosts_with_vuln = [x for x in scan_result if x is not None]

            for ip in hosts_with_vuln:
                print("Vulnerable: {}".format(ip))

if __name__ == '__main__':
    main()
