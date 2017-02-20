#!/usr/bin/env python
#
# signfile.py -- PKCS#11 smartcard signature demo
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
Demonstration how to use PKCS#11 tokens to create signatures with PyKCS11.
"""
__author__ = "Jan Dittberner <jan@dittberner.info>"
import PyKCS11
import argparse
import getpass
import logging
from hashlib import sha256
__all__ = ['PKCS11Signer']
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)-15s [%(levelname)-6s] %(message)s')
class PKCS11Signer(object):
    """Class for signing files using private keys from a PKCS#11 token."""
    def __init__(self, lib=None):
        """
        Initialize the signer, load the PKCS#11 library.
        lib -- PKCS#11 library file
        """
        self.log = logging.getLogger(self.__class__.__name__)
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
    def signFile(self, slot, pin, filehandle):
        """
        Sign a file with the private key from a PKCS#11 token.
        slot -- PKCS#11 slot number
        pin  -- pin for unlocking the slot or None
        filehandle -- file to sign
        """
        self.log.info("Signing file %s", filehandle.name)
        dataHash = sha256()
        dataHash.update(filehandle.read())
        dataToSign = dataHash.digest()
        self.log.debug(
            "SHA-256 digest of file is: 0x%s",
            dataToSign.encode('hex'))
        session = self.pkcs11.openSession(slot)
        if pin is None:
            pin = getpass.getpass("Enter pin code:")
        session.login(pin)
        objects = session.findObjects()
        all_attributes = [
            PyKCS11.CKA_CLASS, PyKCS11.CKA_KEY_TYPE,
            PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT,
            PyKCS11.CKA_MODULUS_BITS]
        for o in objects:
            attributes = session.getAttributeValue(o, all_attributes)
            attrDict = dict(zip(all_attributes, attributes))
            if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY:
                if attrDict[PyKCS11.CKA_KEY_TYPE] == PyKCS11.CKK_RSA:
                    self.log.debug(
                        "Object %d is a RSA private key (%d bits)",
                        o.value(), attrDict[PyKCS11.CKA_MODULUS_BITS])
                    signature = session.sign(o, dataToSign)
                    s = ''.join(chr(c) for c in signature).encode('hex')
                    self.log.debug("Signature is 0x%s", s)
                    sigfilename = '%s.sig' % filehandle.name
                    with open(sigfilename, 'w') as sigf:
                        sigf.write(
                            ''.join(chr(c) for c in signature).encode(
                                'base64'))
                    self.log.info('Signature written to %s', sigfilename)
        session.logout()
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Sign a file using a smartcard")
    parser.add_argument(
        'pkcs11lib', metavar='PKCS11LIB', type=str,
        help='PKCS#11 library file path')
    parser.add_argument(
        '--pin', help='PIN code to unlock the smartcard')
    parser.add_argument(
        'file', type=argparse.FileType('r'),
        help='path to the file to sign')
    parser.set_defaults(pin=None)
    args = parser.parse_args()
    try:
        gi = PKCS11Signer(args.pkcs11lib)
        gi.signFile(0, args.pin, args.file)
    except PyKCS11.PyKCS11Error, e:
        logging.exception("Error")
