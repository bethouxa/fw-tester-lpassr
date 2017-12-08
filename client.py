#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Bethoux Antonin

import socket
from concurrent.futures import ThreadPoolExecutor

import logging
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.WARNING)


def ping(targets):
    """
    :param targets: list of tuples (host, port, proto) to ping
    """
    with ThreadPoolExecutor(max_workers=10) as ex:
        res = ex.map(ping_single, targets)  # Multithreaded map... <3333
    return {targets[index]: r for index, r in enumerate(res)}  # ThreadPoolExecutor.map() returns results in order


def ping_single(target):
    host, port, proto = target
    port = int(port)
    logging.info("Pinging " + str(host) + ":" + str(port))
    s = None
    res = None
    try:
        if proto == "tcp":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            logging.debug("Connected to " + str(host) + ":" + str(port))
            s.send(b"quelle est la couleur du cheval blanc d'henri IV ?\n")
            s.settimeout(5)
        elif proto == 'udp':
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"quelle est la couleur du cheval blanc d'henri IV ?\n", 0, (host, int(port)))
            s.settimeout(5)
            logging.debug("Probe sent, waiting for reply...")
        else:
            raise ValueError(str(proto) + " for " + str(host) + ":" + str(port) + " isn't a valid value. Valid values are 'tcp' and 'udp'")
        r = s.recv(200)
        res = (r.strip() == b'blanc')
    except socket.timeout as toe:
        res = False
    except Exception as e:
        raise e
    finally:
        logging.info(str(host)+":"+proto+"/"+str(port)+" scan finished")
        s.close()
        return res


def displ_pretty(result):
    """

    :param result: dict
    :return:
    """
    columns = max([len(result[ip]) for ip in result])  # highest number of ports scanned for a host
    headColWidth = max([len(ip) for ip in result.keys()])
    ports = set()
    for _, r in result.items():
        for port in r:
            ports.add(port)
    colWidth = max([len(port) for port in ports])

    linesep = "+" + "-" * (headColWidth+2) + "+" + ("-" * (colWidth+2) + "+") * columns
    line = ""

    # Headers
    print(linesep)
    line += "| "+"IP addr".ljust(headColWidth)+" |"
    for port in sorted(ports):
        line += " "+port.ljust(colWidth)+" |"
    print(line)
    print(linesep)

    # Content
    for ip, content in result.items():
        line = ""
        line += "| "+ip.ljust(headColWidth)+ " |"
        for port in sorted(ports):
            if result.get(ip).get(port) is True:
                line += " "+"O".center(colWidth)+" |"
            else:
                line += " "+"X".center(colWidth)+" |"

        print(line)
        print(linesep)


def unflatten_res(results):
    """
    Input : {(ip, port, proto): status}, Output: {ip: proto/port: status}
    :param results:
    :return:
    """
    unfl = {}
    for (ip, port, proto), up in results.items():
        if ip not in unfl:
            unfl[ip] = {}
        unfl[ip][proto+"/"+str(port)] = up
    return unfl


if __name__ == '__main__':
    targets = [
        ('127.0.0.1','8887','tcp'),
        ('127.0.0.1', '8888', 'tcp'),
        ('127.0.0.1', '8889', 'tcp'),
        ('127.0.0.1', '8888', 'udp')
        ]

    displ_pretty(unflatten_res(ping(targets)))

