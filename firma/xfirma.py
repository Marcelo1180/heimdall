import PyKCS11
import sys
import getopt



def dump(src, length=8):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
        N += length
    return result


def usage():
    print "Usage:", sys.argv[0],
    print "[-p pin][--pin=pin]",
    print "[-c lib][--lib=lib]",
    print "[-S][--sign]",
    print "[-d][--decrypt]",
    print "[-h][--help]",

try:
    opts, args = getopt.getopt(sys.argv[1:], "p:c:S:d:h", ["pin=", "lib=", "sign", "decrypt", "help"])
except getopt.GetoptError:
    # print help information and exit:
    usage()
    sys.exit(2)

pin_available = False
decrypt = sign = False
lib = None
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("-p", "--pin"):
        pin = a
        pin_available = True
    elif o in ("-c", "--lib"):
        lib = a
        print "using PKCS11 lib:", lib
    elif o in ("-S", "--sign"):
        sign = True
    elif o in ("-d", "--decrypt"):
        decrypt = True

red = blue = magenta = normal = ""
try:
    pkcslib = PyKCS11.PyKCS11Lib()
    pkcslib.load(lib)
    slots = pkcslib.getSlotList()
    for s in slots:
        session = pkcslib.openSession(s)
        # session.login(pin)
        if pin_available:
            try:
                session.login(pin=pin)
            except:
                print "login failed, exception:", str(sys.exc_info()[1])

            keys = session.findObjects((
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
                (PyKCS11.CKA_SIGN, True),
                # (PyKCS11.CKA_ID, key_id),
            ))
            if not keys:
                raise signers.SigningError("Cannot find the requested key")

            key = keys[0]
            mensaje = "Hola Mundo"
            # signature = bytes(session.sign(key, mensaje, PyKCS11.MechanismRSAPKCS1))
            signature = session.sign(key, mensaje)
            print "Signature:"
            print dump(''.join(map(chr, signature)), 16)
            # objects = session.findObjects()
            # for o in objects:
            #     print
            #     print (red + "==================== Object: %d ====================" + normal) % o.value()

            # print "encrypted:\n", dump(encrypted1, 16)
            decrypted = session.decrypt(key, signature)
            print "decrypted:\n", dump(decrypted1, 16)

except PyKCS11.PyKCS11Error, e:
    print "Error:", e

print "hola"

