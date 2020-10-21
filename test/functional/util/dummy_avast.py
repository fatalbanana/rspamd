#!/usr/bin/env python3

PID = "/tmp/dummy_avast.pid"

import os
import socket
import socketserver
import sys

import dummy_killer

class MyUnixStreamHandler(socketserver.BaseRequestHandler):

    def handle(self):
        self.request.sendall(b"220 DAEMON\r\n")
        self.data = self.request.recv(1024).strip()
        self.request.sendall(b"210 SCAN DATA\r\n")
        if self.server.foundvirus:
            self.request.sendall(b"SCAN /some/path/malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc\t[L]0.0\t0 Eicar\\ [Heur]\r\n")
        else:
            self.request.sendall(b"SCAN /some/path/malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc\t[+]\r\n")
        self.request.sendall(b"200 SCAN OK\r\n")
        self.request.close()

if __name__ == "__main__":

    alen = len(sys.argv)
    if alen > 1:
        port = sys.argv[1]
        if alen >= 3:
            foundvirus = bool(sys.argv[2])
        else:
            foundvirus = False
    else:
        port = "/tmp/dummy_avast.sock"
        foundvirus = False

    server = socketserver.UnixStreamServer(port, MyUnixStreamHandler, bind_and_activate=True)
    server.foundvirus = foundvirus

    dummy_killer.setup_killer(server)
    dummy_killer.write_pid(PID)

    try:
        server.handle_request()
    except socket.error:
        print("Socket closed")

    server.server_close()
    os.remove(port)
