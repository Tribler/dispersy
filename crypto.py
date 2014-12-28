from hashlib import sha1
from math import ceil
from struct import Struct
from json import dumps, loads
import logging

from M2Crypto import EC, BIO
from M2Crypto.EC import EC_pub

import libnacl.dual

from .util import attach_runtime_statistics
from libnacl.encode import hex_decode

_STRUCT_L = Struct(">L")

# Allow all available curves.
# Niels: 16-12-2013, if it starts with NID_
_CURVES = dict((unicode(curve), (getattr(EC, curve), "M2Crypto")) for curve in dir(EC) if curve.startswith("NID_"))

# We want to provide a few default curves.  We will change these curves as new become available and
# old ones to small to provide sufficient security.
_CURVES.update({u"very-low": (EC.NID_sect163k1, "M2Crypto"),
                u"low": (EC.NID_sect233k1, "M2Crypto"),
                u"medium": (EC.NID_sect409k1, "M2Crypto"),
                u"high": (EC.NID_sect571r1, "M2Crypto")})

# Add custom curves, not provided by M2Crypto
_CURVES.update({u'curve25519': (None, "libnacl")})

logger = logging.getLogger(__name__)

class DispersyCrypto(object):

    @property
    def security_levels(self):
        """
        Returns the different security levels supported by this crypto class
        @rtype: [unicode]
        """
        raise NotImplementedError()

    def generate_key(self, security_level):
        """
        Generate a new key using the specified security_level
        @param security_level: Level of security, supported levels can be obtained using .security_levels.
        @type security_level: unicode

        @rtype key
        """
        raise NotImplementedError()

    def key_to_bin(self, key):
        "Convert a key to the binary format."
        raise NotImplementedError()

    def key_to_hash(self, key):
        "Get a hash representation from a key."
        raise NotImplementedError()

    def key_from_public_bin(self, string):
        "Convert a public key stored in the binary format to a key object."
        raise NotImplementedError()

    def key_from_private_bin(self, string):
        "Convert a public/private keypair stored in the binary format to a key object."
        raise NotImplementedError()

    def is_valid_public_bin(self, string):
        "Verify if this binary string contains a public key."
        raise NotImplementedError()

    def is_valid_private_bin(self, string):
        "Verify if this binary string contains a public/private keypair."
        raise NotImplementedError()

    def is_valid_signature(self, key, string, signature):
        "Verify if the signature matches the one generated by key/string pair."
        raise NotImplementedError()

    def create_signature(self, key, string):
        "Create a signature using this key for this string."
        raise NotImplementedError()

    def get_signature_length(self, key):
        "Get the length of a signature created using this key in bytes."
        raise NotImplementedError()


class ECCrypto(DispersyCrypto):
    """
    A crypto object which provides a layer between Dispersy and low level eccrypographic features.
    
    Most methods are implemented by:
        @author: Boudewijn Schoon
        @organization: Technical University Delft
        @contact: dispersy@frayja.com
        
    However since then, most functionality was completely rewritten by:
        @author: Niels Zeilemaker
    """

    def _progress(self, *args):
        "Called when no feedback needs to be given."
        pass

    @property
    def security_levels(self):
        """
        Returns the names of all available curves.
        @rtype: [unicode]
        """
        return _CURVES.keys()

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def generate_key(self, security_level):
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

        @param security_level: Level of security {u'very-low', u'low', u'medium', or u'high'}.
        @type security_level: unicode
        """
        assert isinstance(security_level, unicode)
        assert security_level in _CURVES

        curve = _CURVES[security_level]
        if curve[1] == "M2Crypto":
            return M2CryptoSK(curve[0])

        if curve[1] == "libnacl":
            return LibNaCLSK()

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def key_to_bin(self, ec):
        "Convert the key to a binary format."
        assert isinstance(ec, DispersyKey), ec
        return ec.key_to_bin()

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def key_to_hash(self, ec):
        "Get a hash representation from a key."
        assert isinstance(ec, DispersyKey), ec
        return sha1(ec.pub().key_to_bin()).digest()

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def is_valid_private_bin(self, string):
        "Returns True if the input is a valid public/private keypair stored in a binary format"
        try:
            self.key_from_private_bin(string)
        except Exception as e:
            return False
        return True

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def is_valid_public_bin(self, string):
        "Returns True if the input is a valid public key"
        try:
            self.key_from_public_bin(string)
        except:
            return False
        return True

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def key_from_private_bin(self, string):
        "Get the EC from a public/private keypair stored in a binary format."
        if string.startswith("LibNaCLSK:"):
            return LibNaCLSK(string[10:])
        return M2CryptoSK(keystring=string)

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def key_from_public_bin(self, string):
        "Get the EC from a public key in binary format."
        if string.startswith("LibNaCLPK:"):
            return LibNaCLPK(string[10:])
        return M2CryptoPK(keystring=string)

    def get_signature_length(self, ec):
        """
        Returns the length, in bytes, of each signature made using EC.
        """
        assert isinstance(ec, DispersyKey), ec
        return ec.get_signature_length()

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def create_signature(self, ec, data):
        """
        Returns the signature of DIGEST made using EC.
        """
        assert isinstance(ec, DispersyKey), ec
        assert isinstance(data, str), type(data)
        return ec.signature(data)

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def is_valid_signature(self, ec, data, signature):
        """
        Returns True when SIGNATURE matches the DIGEST made using EC.
        """
        assert isinstance(ec, DispersyKey), ec
        assert isinstance(data, str), type(data)
        assert isinstance(signature, str), type(signature)
        assert len(signature) == self.get_signature_length(ec), [len(signature), self.get_signature_length(ec)]

        try:
            return ec.verify(signature, data)
        except:
            return False

class NoVerifyCrypto(ECCrypto):
    """
    A crypto object which assumes all signatures are valid.  Usefull to reduce CPU overhead.

    """
    def is_valid_signature(self, ec, digest, signature):
        return True


class NoCrypto(NoVerifyCrypto):
    """
    A crypto object which does not create a valid signatures, and assumes all signatures are valid.
    Usefull to reduce CPU overhead.
    """

    def create_signature(self, ec, digest):
        return "0" * self.get_signature_length(ec)


class DispersyKey(object):
    pass

class M2CryptoPK(DispersyKey):

    def __init__(self, ec_pub=None, keystring=None):
        if ec_pub:
            self.ec = ec_pub
        elif keystring:
            self.ec = self.key_from_pem("-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----\n" % keystring.encode("BASE64"))

    def pub(self):
        return self

    def has_secret_key(self):
        return False

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def pem_to_bin(self, pem):
        """
        Convert a key in the PEM format into a key in the binary format.
        @note: Enrcypted pem's are NOT supported and will silently fail.
        """
        return "".join(pem.split("\n")[1:-2]).decode("BASE64")

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def key_to_pem(self):
        "Convert a key to the PEM format."
        bio = BIO.MemoryBuffer()
        self.ec.save_pub_key_bio(bio)
        return bio.read_all()

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def key_from_pem(self, pem):
        "Get the EC from a public PEM."
        return EC.load_pub_key_bio(BIO.MemoryBuffer(pem))

    def key_to_bin(self):
        return self.pem_to_bin(self.key_to_pem())

    def get_signature_length(self):
        return int(ceil(len(self.ec) / 8.0)) * 2

    def verify(self, signature, data):
        length = len(signature) / 2
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

        digest = sha1(data).digest()
        return bool(self.ec.verify_dsa(digest, mpi_r, mpi_s))


class M2CryptoSK(M2CryptoPK):

    def __init__(self, curve=None, keystring=None):
        if curve:
            self.ec = EC.gen_params(curve)
            self.ec.gen_key()

        elif keystring:
            self.ec = self.key_from_pem("-----BEGIN EC PRIVATE KEY-----\n%s-----END EC PRIVATE KEY-----\n" % keystring.encode("BASE64"))

    def pub(self):
        return M2CryptoPK(ec_pub=self.ec.pub())

    def has_secret_key(self):
        return True

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def key_to_pem(self):
        "Convert a key to the PEM format."
        bio = BIO.MemoryBuffer()
        self.ec.save_key_bio(bio, None, lambda *args: "")
        return bio.read_all()

    @attach_runtime_statistics(u"{0.__class__.__name__}.{function_name}")
    def key_from_pem(self, pem):
        "Get the EC from a public/private keypair stored in the PEM."
        def get_password(*args):
            return ""
        return EC.load_key_bio(BIO.MemoryBuffer(pem), get_password)

    def signature(self, msg):
        length = int(ceil(len(self.ec) / 8.0))
        digest = sha1(msg).digest()

        mpi_r, mpi_s = self.ec.sign_dsa(digest)
        length_r, = _STRUCT_L.unpack_from(mpi_r)
        r = mpi_r[-min(length, length_r):]
        length_s, = _STRUCT_L.unpack_from(mpi_s)
        s = mpi_s[-min(length, length_s):]

        return "".join(("\x00" * (length - len(r)), r, "\x00" * (length - len(s)), s))


class LibNaCLPK(DispersyKey):

    def __init__(self, json={}, hex_pk=None, hex_vk=None):
        if json:
            json = loads(json)

        self.crypt = libnacl.public.PublicKey(hex_decode(json.get('pk', hex_pk)))
        self.veri = libnacl.sign.Verifier(json.get('vk', hex_vk))

    def pub(self):
        return self

    def has_secret_key(self):
        return False

    def verify(self, signature, msg):
        return self.veri.verify(signature + msg)

    def key_to_bin(self):
        return "LibNaCLPK:" + dumps({'pk': self.crypt.hex_pk(), 'vk': self.veri.hex_vk()})

    def get_signature_length(self):
        return libnacl.crypto_sign_BYTES


class LibNaCLSK(LibNaCLPK):

    def __init__(self, json={}):
        if json:
            json = loads(json)
            self.key = libnacl.dual.DualSecret(hex_decode(json['crypt']), hex_decode(json['seed']))
        else:
            self.key = libnacl.dual.DualSecret()
        self.veri = libnacl.sign.Verifier(self.key.hex_vk())

    def pub(self):
        return LibNaCLPK(hex_pk=self.key.hex_pk(), hex_vk=self.key.hex_vk())

    def has_secret_key(self):
        return True

    def signature(self, msg):
        return self.key.signature(msg)

    def key_to_bin(self):
        return "LibNaCLSK:" + dumps({'crypt': self.key.hex_sk(), 'seed': self.key.hex_seed()})
