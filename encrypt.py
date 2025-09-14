#!/usr/bin/env python3
import sys

key = "MySuperSecretKey123!"
with open('payload.bin', 'rb') as f:
    data = bytearray(f.read())

for i in range(len(data)):
    data[i] ^= ord(key[i % len(key)])

with open('payload_encrypted.bin', 'wb') as f:
    f.write(data)
print("[+] Payload encrypted and saved to payload_encrypted.bin")
