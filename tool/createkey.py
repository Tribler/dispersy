#!/usr/bin/env python2

"""
Create one or more Elliptic Curves.

Typically the following curves are used:
- very-low: NID_sect163k1  ~42 byte signatures
- low:      NID_sect233k1  ~60 byte signatures
- medium:   NID_sect409k1 ~104 byte signatures
- high:     NID_sect571r1 ~144 byte signatures
"""

import argparse
import time
from hashlib import sha1

from M2Crypto import EC
# From: http://docs.python.org/2/tutorial/modules.html#intra-package-references
# Note that both explicit and implicit relative imports are based on the name of the current
# module. Since the name of the main module is always "__main__", modules intended for use as the
# main module of a Python application should always use absolute imports.
from dispersy.crypto import ECCrypto, _CURVES

def ec_name(eccrypto, curve):
    assert isinstance(curve, unicode)
    curve_id = _CURVES[curve]

    for name in dir(EC):
        value = getattr(EC, name)
        if isinstance(value, int) and value == curve_id:
            return name

def create_key(eccrypto, curves):
    for index, curve in enumerate(curves):
        if index > 0:
            print

        private_pem = ""
        public_pem = ""

        ec = eccrypto.generate_key(curve)
        if hasattr(ec, 'key_to_pem'):
            print "KEP"
            private_pem = ec.key_to_pem()
            public_pem = ec.pub().key_to_pem()

        private_bin = eccrypto.key_to_bin(ec)
        public_bin = eccrypto.key_to_bin(ec.pub())
        print "generated:", time.ctime()
        print "curve:", ec_name(eccrypto, curve)
        print "len:", len(ec.ec), "bits ~", eccrypto.get_signature_length(ec), "bytes signature"
        print "pub:", len(public_bin), public_bin.encode("HEX")
        print "prv:", len(private_bin), private_bin.encode("HEX")
        print "pub-sha1", sha1(public_bin).digest().encode("HEX")
        print "prv-sha1", sha1(private_bin).digest().encode("HEX")
        print public_pem.strip()
        print private_pem.strip()

def main():
    eccrypto = ECCrypto()

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("curves",
                        metavar="CURVE",
                        nargs="+",
                        choices=sorted([str(curve) for curve in eccrypto.security_levels]),
                        help="EC curves to create")
    args = parser.parse_args()

    create_key(eccrypto, (unicode(curve) for curve in args.curves))

if __name__ == "__main__":
    main()
