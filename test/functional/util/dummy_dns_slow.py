#!/usr/bin/env python3

"""
Mock DNS server that triggers partial writes in DNS over TCP.
This server deliberately uses small send buffers and writes data in small chunks
to trigger the partial write bug that was fixed in contrib/librdns/resolver.c

The bug was: ntohs(oc->next_write_size) < oc->cur_write
Should be:    ntohs(oc->next_write_size) + sizeof(oc->next_write_size) <= oc->cur_write

The issue is that DNS over TCP has a 2-byte size prefix before each DNS packet.
The old code didn't account for this when checking if a packet was fully written.
"""

import socket
import struct
import time
import sys
import os
import dummy_killer

PID = "/tmp/dummy_dns_slow.pid"

# Simple DNS response generator
def create_txt_response(query_id, qname, txt_records):
    """Create a DNS TXT response with multiple TXT records"""
    
    # DNS Header (12 bytes)
    # ID (2 bytes) + Flags (2 bytes) + QDCOUNT (2) + ANCOUNT (2) + NSCOUNT (2) + ARCOUNT (2)
    flags = 0x8180  # Standard query response, no error
    qdcount = 1
    ancount = len(txt_records)
    nscount = 0
    arcount = 0
    
    header = struct.pack('!HHHHHH', query_id, flags, qdcount, ancount, nscount, arcount)
    
    # Question section - echo back the query
    question = qname
    question += struct.pack('!HH', 16, 1)  # Type TXT (16), Class IN (1)
    
    # Answer section - multiple TXT records
    answers = b''
    for txt in txt_records:
        # Name (pointer to question)
        answers += b'\xc0\x0c'  # Pointer to offset 12 (question name)
        
        # Type TXT (16), Class IN (1), TTL (4 bytes), RDLENGTH (2 bytes)
        ttl = 300
        txt_data = txt.encode('utf-8')
        # TXT format: length byte + data
        txt_rdata = bytes([len(txt_data)]) + txt_data
        rdlength = len(txt_rdata)
        
        answers += struct.pack('!HHIH', 16, 1, ttl, rdlength)
        answers += txt_rdata
    
    response = header + question + answers
    return response

def encode_domain_name(domain):
    """Encode domain name in DNS format: length-prefixed labels"""
    parts = domain.split('.')
    encoded = b''
    for part in parts:
        encoded += bytes([len(part)]) + part.encode('ascii')
    encoded += b'\x00'  # Null terminator
    return encoded

def handle_dns_query(data):
    """Parse DNS query and generate response"""
    if len(data) < 12:
        return None
    
    # Parse header
    query_id = struct.unpack('!H', data[0:2])[0]
    
    # For simplicity, we'll just respond to any TXT query with large records
    # Generate many TXT records to make response large (>512 bytes to trigger TCP)
    txt_records = [
        "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 include:_spf1.example.com include:_spf2.example.com include:_spf3.example.com ~all",
        "google-site-verification=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "MS=ms12345678",
        "apple-domain-verification=ABCDEFGHIJKLMNOPabcdefgh",
        "facebook-domain-verification=abcdefghijklmnopqrstuvwxyz123456",
        "atlassian-domain-verification=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
        "stripe-verification=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "docusign=12345678-1234-1234-1234-123456789abc",
        "zoom-domain-verification=abcdefghijklmnopqrstuvwxyz",
        "slack-verification-code=abcdefghijklmnopqrstuvwxyz123456",
    ]
    
    # Get query name from question section (skip parsing, use dummy)
    qname = encode_domain_name("test.example.com")
    
    return create_txt_response(query_id, qname, txt_records)

def handle_client(client_sock, addr):
    """Handle a single DNS over TCP client with deliberate partial writes"""
    print(f"[+] Connection from {addr}")
    
    try:
        # Read the 2-byte length prefix
        len_data = client_sock.recv(2)
        if len(len_data) != 2:
            print(f"[-] Failed to read length prefix from {addr}")
            return
        
        query_len = struct.unpack('!H', len_data)[0]
        print(f"[+] Query length: {query_len}")
        
        # Read the DNS query
        query_data = b''
        while len(query_data) < query_len:
            chunk = client_sock.recv(query_len - len(query_data))
            if not chunk:
                break
            query_data += chunk
        
        print(f"[+] Received {len(query_data)} bytes of query")
        
        # Generate response
        response = handle_dns_query(query_data)
        if not response:
            print(f"[-] Failed to generate response for {addr}")
            return
        
        print(f"[+] Generated response: {len(response)} bytes")
        
        # Prepare response with 2-byte length prefix
        response_len = struct.pack('!H', len(response))
        full_response = response_len + response
        
        # **TRIGGER PARTIAL WRITES**
        # Set very small send buffer to force partial writes
        client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64)
        
        # Send data in very small chunks with delays to trigger partial writes
        bytes_sent = 0
        chunk_size = 1  # Send 1 byte at a time initially
        
        while bytes_sent < len(full_response):
            # Vary chunk size: 1 byte, then 2, then 3, etc.
            chunk_size = min(1 + (bytes_sent % 5), len(full_response) - bytes_sent)
            chunk = full_response[bytes_sent:bytes_sent + chunk_size]
            
            # Small delay between sends to increase chance of partial write
            time.sleep(0.01)
            
            sent = client_sock.send(chunk)
            bytes_sent += sent
            print(f"[+] Sent {sent} bytes (total: {bytes_sent}/{len(full_response)})")
            
            if sent < len(chunk):
                print(f"[!] Partial write detected: tried {len(chunk)}, sent {sent}")
        
        print(f"[+] Response sent successfully to {addr}")
        
    except Exception as e:
        print(f"[-] Error handling client {addr}: {e}")
    finally:
        client_sock.close()

def main():
    port = 15353  # Use non-standard port
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    
    # Create TCP socket for DNS
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind and listen
    server_sock.bind(('127.0.0.1', port))
    server_sock.listen(5)
    
    print(f"[*] DNS TCP server listening on 127.0.0.1:{port}")
    dummy_killer.write_pid(PID)
    
    try:
        while True:
            client_sock, addr = server_sock.accept()
            handle_client(client_sock, addr)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()
