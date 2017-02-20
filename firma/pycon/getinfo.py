#!/usr/bin/env python
#
# getinfo.py -- get information about available PKCS#11 tokens
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
Utility to get information about available PKCS#11 tokens.
"""
__author__ = "Jan Dittberner <jan@dittberner.info>"
import PyKCS11
import argparse
import getpass
import logging
import sys
__all__ = ['PKCS11Info']
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)-15s [%(levelname)-6s] %(message)s')
class PKCS11Info(object):
    """PKCS#11 information gatherer."""
    def __init__(self, lib):
        """
        Load PKCS#11 library.
        """
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
        self.log = logging.getLogger(self.__class__.__name__)
    def getSlotInfo(self, slot):
        """
        Get info about PKCS#11 token slot
        slot -- slot number
        """
        slotinfo = self.pkcs11.getSlotInfo(slot)
        self.log.info(
            "Slot information for slot %d: %s", slot, slotinfo)
        return slotinfo
    def getTokenInfo(self, slot):
        """
        Get token information for token in slot.
        slot -- slot number
        """
        self.log.info(
            "Token info for slot %d: %s",
            slot, self.pkcs11.getTokenInfo(slot))
    def getMechanismInfo(self, slot):
        """
        Get mechanisms of token in slot.
        slot -- slot number
        """
        from StringIO import StringIO
        buf = StringIO()
        print >> buf, "Mechanism list for slot %d:" % slot
        m = self.pkcs11.getMechanismList(slot)
        for x in m:
            print >> buf, x
            i = self.pkcs11.getMechanismInfo(slot, x)
            if not i.flags & PyKCS11.CKF_DIGEST:
                if i.ulMinKeySize != PyKCS11.CK_UNAVAILABLE_INFORMATION:
                    print >> buf, "  ulMinKeySize:", i.ulMinKeySize
                if i.ulMaxKeySize != PyKCS11.CK_UNAVAILABLE_INFORMATION:
                    print >> buf, "  ulMaxKeySize:", i.ulMaxKeySize
                print >> buf, "  flags:", ", ".join(i.flags2text())
        self.log.info(buf.getvalue())
    def getInfo(self):
        self.log.info(self.pkcs11.getInfo())
    def getSessionInfo(self, slot):
        """
        Get session info for slot.
        slot -- slot number
        """
        session = self.pkcs11.openSession(slot)
        pin = getpass.getpass("Enter pin code for slot %d:" % slot)
        session.login(pin)
        self.log.info(
            "Session info for slot %d: %s", slot, session.getSessionInfo())
        session.logout()
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Get information about available PKCS#11 tokens")
    parser.add_argument(
        'pkcs11lib', metavar='PKCS11LIB', type=str,
        help='PKCS#11 library file path')
    args = parser.parse_args()
    try:
        gi = PKCS11Info(args.pkcs11lib)
        gi.getInfo()
        slots = gi.pkcs11.getSlotList()
    except PyKCS11.PyKCS11Error, e:
        logging.exception("Error:")
        sys.exit(1)
    logging.info("Available Slots: %d, %s", len(slots), slots)
    if len(slots) == 0:
        sys.exit(2)
    for slot in slots:
        try:
            slotinfo = gi.getSlotInfo(slot)
            if not 'CKF_TOKEN_PRESENT' in slotinfo.flags2text():
                logging.info('No token in slot %d', slot)
            else:
                gi.getSessionInfo(slot)
                gi.getTokenInfo(slot)
                gi.getMechanismInfo(slot)
        except PyKCS11.PyKCS11Error, e:
            logging.exception("Error:")
