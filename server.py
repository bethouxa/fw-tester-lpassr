#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Béthoux Antonin

import socketserver
from threading import Thread
import logging

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


class ThreadingTCPServerWith(socketserver.ThreadingTCPServer):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server_close()


class PongRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        ping = self.rfile.readline(200)
        if ping.strip() == b"quelle est la couleur du cheval blanc d'henri IV ?":
            self.wfile.write(b'blanc')
            logging.info("Received ping from "+str(self.client_address))


def run(port_list):
    servers = {}
    for port in port_list:
        servers[port] = Thread(target=run_single, args=[*port])
        servers[port].start()
        logging.info("Server started on port "+str(port))


def run_single(port, proto):
    if proto == 'tcp':
        server = socketserver.ThreadingTCPServer
    elif proto == 'udp':
        server = socketserver.ThreadingUDPServer
    else:
        raise ValueError(proto+" is not a valid protocol.")

    s = server(('0.0.0.0', port), PongRequestHandler)
    s.serve_forever()
    s.server_close()


if __name__ == '__main__':
    run([
        (8888, 'tcp'),
        (8889, 'tcp'),
        (8887, 'tcp'),
        (8888, 'udp'),
    ])
