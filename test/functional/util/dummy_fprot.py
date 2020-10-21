#!/usr/bin/env python3

import os
import signal
import socket
import socketserver
import sys

import dummy_killer

PID = "/tmp/dummy_fprot.pid"

class MyUnixStreamHandler(socketserver.BaseRequestHandler):

    def handle(self):
        self.data = self.request.recv(1024).strip()
        if self.server.foundvirus:
            self.request.sendall(b"1 <infected: EICAR_Test_File> FOO->bar\n")
        else:
            self.request.sendall(b"0 <clean> FOO\n")
        self.request.close()

if __name__ == "__main__":

    alen = len(sys.argv)
    if alen > 1:
        port = sys.argv[1]
        if alen >= 4:
            PID = sys.argv[3]
            foundvirus = bool(sys.argv[2])
        elif alen >= 3:
            foundvirus = bool(sys.argv[2])
        else:
            foundvirus = False
    else:
        port = "/tmp/fake_fprot.sock"
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
