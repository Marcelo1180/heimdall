#!/usr/bin/env python
#
# verifysignature.py -- verify a SHA256/RSA signature of a file
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
Demonstration how to use PyCrypto to verify a SHA256/RSA signature.
"""
__author__ = "Jan Dittberner <jan@dittberner.info>"
from Crypto.PublicKey import RSA
from hashlib import sha256
from util import pkcs1unpad
import argparse
import logging
__all__ = ['Verifier']
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)-15s [%(levelname)-6s] %(message)s')
class Verifier(object):
    """Verify a file's SHA-256-RSA signature with PKCS#1 padding."""
    def __init__(self, keyfile):
        """
        Initialize the verifier, load public key and setup logging.
        keyfile -- file handle for the public key
        """
        self.pubkey = RSA.importKey(keyfile.read())
        self.log = logging.getLogger(self.__class__.__name__)
    def _calculate_hash(self, filehandle):
        """
        Calculate the SHA-256 hash of the file.
        filehandle -- file object
        """
        sha = sha256()
        sha.update(filehandle.read())
        return sha.digest()
    def verify(self, filehandle):
        """
        Verify the SHA-256-RSA signature for file using file.sig
        filehandle -- the file to check against its file.sig
        """
        hashvalue = self._calculate_hash(filehandle)
        with open('%s.sig' % filehandle.name, 'r') as f:
            signature = eval("0x%s" % f.read().decode('base64').encode('hex'))
        self.log.debug("Public Key: %s (%d bits)",
                       self.pubkey, self.pubkey.size() + 1)
        self.log.debug("Hash data: 0x%s", hashvalue.encode('hex'))
        self.log.debug("Signature: 0x%x", signature)
        decrypted = (
            "00020%x" % self.pubkey.encrypt(signature, '')).decode('hex')
        return pkcs1unpad(decrypted) == hashvalue
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Check a signature from a file using an RSA public key")
    parser.add_argument(
        'pubkey', help='RSA public key file', type=argparse.FileType('r'))
    parser.add_argument(
        'file', help='file to be verified', type=argparse.FileType('r'))
    args = parser.parse_args()
    verifier = Verifier(args.pubkey)
    if verifier.verify(args.file):
        logging.info('Signature is good')
    else:
        logging.info('Signature is broken')
