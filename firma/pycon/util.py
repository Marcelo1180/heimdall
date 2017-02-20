#!/usr/bin/env python
#
# util.py -- utility functions for cryptography
#
# Copyright (C) 2011 Jan Dittberner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
This module provides cryptography utility functions.
"""
import random
import logging
logger = logging.getLogger(__name__)
def pkcs1pad(source, k):
    """Apply PKCS#1 padding to source to pad it to length k.
    source -- source bytes
    k -- length of result (usually key bytes)
    """
    if (isinstance(source, unicode)):
        source = source.encode('utf-8')
    if k < (len(source) - 3 - 8):
        raise ValueError("too many bytes for RSA operation")
    eb = []
    eb.append(chr(0x00))
    eb.append(chr(0x02))
    padbytes = k - 3 - len(source)
    eb.extend([chr(random.randint(1, 255)) for byte in xrange(padbytes)])
    eb.append(chr(0x00))
    eb.extend(source)
    return "".join(eb)
def pkcs1unpad(source):
    """
    Remove PKCS#1 padding from source.
    source -- source bytes
    """
    if source[0] != chr(0x00) or source[1] != chr(0x02):
        logger.error("first bytes to unpad %r", [ord(c) for c in source[0:2]])
        raise ValueError("invalid PKCS#1 padding")
    for pos in xrange(2, len(source)):
        if source[pos] == chr(0x00):
            return "".join(source[pos + 1:])
    return None
def pkcs5pad(source):
    """
    Apply PKCS#5 padding to 16 byte boundaries.
    source -- source bytes
    """
    if isinstance(source, unicode):
        result = source.encode('utf-8')
    else:
        result = source
    # pad to full 16 byte boundary, add a full block of padding bytes if the
    # source length is exactly at a 16 byte boundary
    padbytes = (16 - (len(result) % 16)) or 16
    result += (padbytes * chr(padbytes))
    return result
def pkcs5unpad(source):
    """
    Remove PKCS#5 padding.
    source -- source bytes
    """
    padbytes = ord(source[-1])
    return source[:-padbytes]
