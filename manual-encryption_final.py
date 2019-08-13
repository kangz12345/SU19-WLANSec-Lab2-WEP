#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""


from scapy.all import *
import binascii
import rc4
import random

# wep key AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'


arp = rdpcap('arp.cap')[0]

# The message that I want to encrypt
message = "SU 2019".ljust(36, '\0')[:36]

# ICV
icv = binascii.crc32(message) & 0xffffffff
to_enc_icv = struct.pack('<L', icv)

# msg + icv
to_encrypt = message + to_enc_icv

# IV
iv = arp.iv	

# The rc4 seed is composed by the IV+key
seed = iv+key 

#to_encrypt = message+icv
encrypted = rc4.rc4crypt(to_encrypt, seed)

#restructuring the ICV
icv_num = encrypted[-4:]
icv_num, = struct.unpack('!L', icv_num)

#forging the packet
arp.wepdata = encrypted[:-4]
arp.icv = icv_num

#writing the pcap file
wrpcap('su19.cap', arp)

