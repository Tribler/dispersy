"""
The crypto module provides a layer between Dispersy and low level crypographic features.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""

from math import ceil
from M2Crypto import EC, BIO
from struct import Struct

_STRUCT_L = Struct(">L")

# Allow all available curves.
_CURVES = dict((unicode(curve), getattr(EC, curve)) for curve in dir(EC) if curve.startswith("NID_"))

# We want to provide a few default curves.  We will change these curves as new become available and
# old ones to small to provide sufficient security.
_CURVES.update({u"very-low": EC.NID_sect163k1,
                u"low": EC.NID_sect233k1,
                u"medium": EC.NID_sect409k1,
                u"high": EC.NID_sect571r1})

def _progress(*args):
    "Called when no feedback needs to be given."
    pass

def ec_get_curves():
    """
    Returns the names of all available curves.
    @rtype: [unicode]
    """
    return _CURVES.keys()

def ec_generate_key(security):
    """
    Generate a new Elliptic Curve object with a new public / private key pair.

    Security can be u'low', u'medium', or u'high' depending on how secure you need your Elliptic
    Curve to be.  Currently these values translate into:
        - very-low: NID_sect163k1  ~42 byte signatures
        - low:      NID_sect233k1  ~60 byte signatures
        - medium:   NID_sect409k1 ~104 byte signatures
        - high:     NID_sect571r1 ~144 byte signatures

    Besides these predefined curves, all other curves provided by M2Crypto are also available.  For
    a full list of available curves, see ec_get_curves().

    @param security: Level of security {u'very-low', u'low', u'medium', or u'high'}.
    @type security: unicode

    @note that the NID must always be 160 bits or more, otherwise it will not be able to sign a sha1
        digest.
    """
    assert isinstance(security, unicode)
    assert security in _CURVES
    ec = EC.gen_params(_CURVES[security])
    ec.gen_key()
    return ec

def ec_public_pem_to_public_bin(pem):
    "Convert a public key in PEM format into a public key in binary format."
    return "".join(pem.split("\n")[1:-2]).decode("BASE64")

def ec_private_pem_to_private_bin(pem):
    """
    Convert a private key in PEM format into a private key in binary format.

    @note: Enrcypted pem's are NOT supported and will silently fail.
    """
    return "".join(pem.split("\n")[1:-2]).decode("BASE64")

def ec_to_private_pem(ec, cipher=None, password=None):
    "Get the private key in PEM format."
    def get_password(*args):
        return password or ""
    bio = BIO.MemoryBuffer()
    ec.save_key_bio(bio, cipher, get_password)
    return bio.read_all()

def ec_to_public_pem(ec):
    "Get the public key in PEM format."
    bio = BIO.MemoryBuffer()
    ec.save_pub_key_bio(bio)
    return bio.read_all()

def ec_from_private_pem(pem, password=None):
    "Get the EC from a private PEM."
    def get_password(*args):
        return password or ""
    return EC.load_key_bio(BIO.MemoryBuffer(pem), get_password)

def ec_from_public_pem(pem):
    "Get the EC from a public PEM."
    return EC.load_pub_key_bio(BIO.MemoryBuffer(pem))

def ec_check_private_pem(pem):
    "Returns True if the input is a valid private key"
    try:
        ec_from_private_pem(pem)
    except:
        return False
    return True

def ec_check_public_pem(pem):
    "Returns True if the input is a valid public key"
    try:
        ec_from_public_pem(pem)
    except:
        return False
    return True

def ec_to_private_bin(ec):
    "Get the private key in binary format."
    return ec_private_pem_to_private_bin(ec_to_private_pem(ec))

def ec_to_public_bin(ec):
    "Get the public key in binary format."
    return ec_public_pem_to_public_bin(ec_to_public_pem(ec))

def ec_check_private_bin(string):
    "Returns True if the input is a valid private key"
    try:
        ec_from_private_bin(string)
    except:
        return False
    return True

def ec_check_public_bin(string):
    "Returns True if the input is a valid public key"
    try:
        ec_from_public_bin(string)
    except:
        return False
    return True

def ec_from_private_bin(string):
    "Get the EC from a private key in binary format."
    return ec_from_private_pem("".join(("-----BEGIN EC PRIVATE KEY-----\n",
                                        string.encode("BASE64"),
                                        "-----END EC PRIVATE KEY-----\n")))

def ec_from_public_bin(string):
    "Get the EC from a public key in binary format."
    return ec_from_public_pem("".join(("-----BEGIN PUBLIC KEY-----\n",
                                       string.encode("BASE64"),
                                       "-----END PUBLIC KEY-----\n")))

def ec_signature_length(ec):
    """
    Returns the length, in bytes, of each signature made using EC.
    """
    return int(ceil(len(ec) / 8.0)) * 2

def ec_sign(ec, digest):
    """
    Returns the signature of DIGEST made using EC.
    """
    assert isinstance(digest, str), type(digest)
    length = int(ceil(len(ec) / 8.0))

    mpi_r, mpi_s = ec.sign_dsa(digest)
    length_r, = _STRUCT_L.unpack_from(mpi_r)
    r = mpi_r[-min(length, length_r):]
    length_s, = _STRUCT_L.unpack_from(mpi_s)
    s = mpi_s[-min(length, length_s):]

    return "".join(("\x00" * (length - len(r)), r, "\x00" * (length - len(s)), s))

def ec_verify(ec, digest, signature):
    """
    Returns True when SIGNATURE matches the DIGEST made using EC.
    """
    assert isinstance(digest, str), type(digest)
    assert isinstance(signature, str), type(signature)
    assert len(signature) == ec_signature_length(ec), [len(signature), ec_signature_length(ec)]
    length = len(signature) / 2
    try:
        r = signature[:length]
        # remove all "\x00" prefixes
        while r and r[0] == "\x00":
            r = r[1:]
        # prepend "\x00" when the most significant bit is set
        if ord(r[0]) & 128:
            r = "\x00" + r

        s = signature[length:]
        # remove all "\x00" prefixes
        while s and s[0] == "\x00":
            s = s[1:]
        # prepend "\x00" when the most significant bit is set
        if ord(s[0]) & 128:
            s = "\x00" + s

        mpi_r = _STRUCT_L.pack(len(r)) + r
        mpi_s = _STRUCT_L.pack(len(s)) + s

        # mpi_r3 = bn_to_mpi(bin_to_bn(signature[:length]))
        # mpi_s3 = bn_to_mpi(bin_to_bn(signature[length:]))

        # if not mpi_r == mpi_r3:
        #     raise RuntimeError([mpi_r.encode("HEX"), mpi_r3.encode("HEX")])
        # if not mpi_s == mpi_s3:
        #     raise RuntimeError([mpi_s.encode("HEX"), mpi_s3.encode("HEX")])

        return bool(ec.verify_dsa(digest, mpi_r, mpi_s))

    except:
        return False
