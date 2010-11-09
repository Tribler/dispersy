from random import randint
from hashlib import sha1, sha224, sha256, sha512, md5
import M2Crypto

def _progress(*args):
    pass

def _uint_to_binary16(value):
    """
    Convert a positive integer into 2 bytes in big-endian order.
    """
    assert isinstance(value, int), "VALUE has invalid type: %s" % type(value)
    assert value >= 0, "VALUE has invalid value: %d" % value
    return chr((value >> 8) & 0xFF) + chr(value & 0xFF)

def _binary16_to_uint(stream, offset=0):
    """
    Convert 2 bytes, starting at OFFSET and assuming big-endian order,
    from STREAM into an unsigned integer.
    """
    assert isinstance(stream, bytes), "STREAM has invalid type: %s" % type(stream)
    assert isinstance(offset, int), "OFFSET has invalid type: %s" % type(offset)
    assert len(stream) >= offset + 2, "STREAM has invalid length: %d" % len(stream)
    return ord(stream[offset]) << 8 | ord(stream[offset+1])

def rsa_generate_key(bits=1024, exponent=5, progress=None):
    """
    Generate a new RSA public / private key pair.

    Note: with RSA it is dangerous to use a small exponent to encrypt
    the same message to multiple recipients, as this can lead to an
    algebraic attack.
    """
    assert isinstance(bits, (int, long))
    assert bits % 8 == 0
    assert isinstance(exponent, int)
    assert progress is None or callable(progress)
    # assert bits >= 512, "Need at least 512 bits to sign sha1 message digests"
    return M2Crypto.RSA.gen_key(bits, exponent, progress or _progress)

def rsa_to_private_pem(rsa, cipher="aes_128_cbc", password=None):
    """
    Get the private key in binary format from RSA.
    """
    assert isinstance(rsa, M2Crypto.RSA.RSA)
    assert password is None or isinstance(password, str)
    def get_password(*args):
        return password or "-empty-"
    bio = M2Crypto.BIO.MemoryBuffer()
    rsa.save_key_bio(bio, cipher, get_password)
    return bio.read_all()

def rsa_to_private_bin(rsa, cipher="aes_128_cbc", password=None):
    pem = rsa_to_private_pem(rsa, cipher, password)
    lines = pem.split("\n")
    return "".join(lines[4:-2]).decode("BASE64")

# def rsa_to_private_der(rsa):
#     """
#     Get the private key in binary format from RSA.
#     """
#     assert isinstance(rsa, M2Crypto.RSA.RSA)
#     bio = M2Crypto.BIO.MemoryBuffer()
#     rsa.save_key_der_bio(bio)
#     return bio.read_all()

def rsa_to_public_pem(rsa, cipher="aes_128_cbc", password=None):
    """
    Get the public key in binary format from RSA.

    # note: for some reason the M2Crypto interface does not allow us
    # to set the cipher or the password.  These two parameters are
    # therefore ignored.
    """
    assert isinstance(rsa, M2Crypto.RSA.RSA)
    assert password is None or isinstance(password, str)
    bio = M2Crypto.BIO.MemoryBuffer()
    rsa.save_pub_key_bio(bio)
    return bio.read_all()

def rsa_to_public_bin(rsa, cipher="aes_128_cbc", password=None):
    pem = rsa_to_public_pem(rsa, cipher, password)
    lines = pem.split("\n")
    return "".join(lines[1:-2]).decode("BASE64")
    
def rsa_from_private_pem(pem, password=None):
    """
    Create a RSA public / private key pair from a PEM binary string.
    """
    assert isinstance(pem, str)
    assert password is None or isinstance(password, str)
    def get_password(*args):
        return password or "-empty-"
    return M2Crypto.RSA.load_key_bio(M2Crypto.BIO.MemoryBuffer(pem), get_password)

def rsa_from_public_pem(pem):
    """
    Create a RSA public part from a PEM binary string.
    """
    assert isinstance(pem, str)
    return M2Crypto.RSA.load_pub_key_bio(M2Crypto.BIO.MemoryBuffer(pem))

def rsa_encrypt(rsa, data):
    """
    RSA can only encrypt data that is the same length as it has bits.
    This function adds padding and encypts longer DATA in multiple
    passes.

    Resulting encrypted data will contain, in sequence, two bytes
    indicating len(DATA), followed by DATA, followed by random
    padding.
    """
    # TODO: use standard!
    assert isinstance(rsa, M2Crypto.RSA.RSA)
    assert len(rsa) % 8 == 0
    assert isinstance(data, str)
    assert len(data) < 2 ** 16
    chunk_length = len(rsa) / 8
    data = _uint_to_binary16(len(data)) + data + "".join((chr(randint(0, 255)) for _ in xrange(chunk_length - len(data) % chunk_length - 2)))
    return "".join((rsa.private_encrypt(data[offset:offset+chunk_length], M2Crypto.RSA.no_padding) for offset in xrange(0, len(data), chunk_length)))

def rsa_decrypt(rsa, data):
    """
    RSA can only encrypt data that is the same length as it has bits.
    This function removes padding and decypts longer DATA in multiple
    passes.
    """
    # TODO: use standard!
    assert isinstance(rsa, M2Crypto.RSA.RSA)
    assert len(rsa) % 8 == 0
    assert isinstance(data, str)
    chunk_length = len(rsa) / 8
    data = "".join((rsa.public_decrypt(data[offset:offset+chunk_length], M2Crypto.RSA.no_padding) for offset in xrange(0, len(data), chunk_length)))
    return data[2:_binary16_to_uint(data)+2]

# def choose_digest_method(rsa):
#     """
#     returns a hashlib digest method and its corresponding name.

#     When signing, the message (or digest) that is signed must always
#     be 11 bytes smaller than the RSA key.  11 bytes is the minimal
#     amount of bytes required for the header / padding.

#     Possible return values are:
#     - (hashlib.sha1, 'sha1')
#     - (hashlib.sha224, 'sha224')
#     - (hashlib.sha256, 'sha256')
#     - (hashlib.sha512, 'sha512')
#     """
#     assert isinstance(rsa, M2Crypto.RSA.RSA)
#     assert len(rsa) % 8 == 0
#     length = len(rsa) / 8
#     if length > 64 + 25: return (sha512, "sha512")
#     if length > 32 + 25: return (sha256, "sha256")
#     if length > 28 + 25: return (sha224, "sha224")
#     if length > 20 + 25: return (sha1, "sha1")
#     raise ValueError("This data length can not be signed using a RSA key with this length")

if __name__ == "__main__":
    # bits = 1024
    # exponent = 5
    # rsa = rsa_generate_key(bits, exponent)
    # public_pem = rsa_to_public_pem(rsa)
    # public_bin = rsa_to_public_bin(rsa)
    # private_pem = rsa_to_private_pem(rsa)
    # private_bin = rsa_to_private_bin(rsa)

    # print "Generating public / private key pair"
    # print "Bits:", bits
    # print "Exponent:", exponent
    # print "SHA1(pub-pem).HEX:", len(public_pem), sha1(public_pem).digest().encode("HEX")
    # print "SHA1(pub-str).HEX:", len(public_bin), sha1(public_bin).digest().encode("HEX")
    # print "SHA1(prv-pem).HEX:", len(private_pem), sha1(private_pem).digest().encode("HEX")
    # print "SHA1(prv-str).HEX:", len(private_bin), sha1(private_bin).digest().encode("HEX")
    # print public_pem
    # print private_pem

    # data = "Hello World! " * 1000
    # digest = sha1(data).digest()

    # for bits in reversed([31*8, 256, 512, 1024, 2048]):
    #     rsa = rsa_generate_key(bits, 5)

    #     # sig = rsa.sign(digest, "sha1")
    #     sig = ""
    #     enc = rsa.private_encrypt(digest, M2Crypto.RSA.pkcs1_padding)

    #     print "BITS:", bits, "BYTES:", bits / 8, "PUBLIC-PEM:", len(rsa_to_public_pem(rsa)), "MESSAGE:", len(data), "DIGEST:", len(digest), "SIG:", len(sig), "ENC:", len(enc)

    # # smallest sha1 (20 bytes)
    # bits = 20 * 8
    # rsa = rsa_generate_key(bits, 5)
    # digest = sha1(data).digest()
    # sig = ""
    # enc = rsa.private_encrypt(digest, M2Crypto.RSA.no_padding)
    # print "BITS:", bits, "BYTES:", bits / 8, "PUBLIC-PEM:", len(rsa_to_public_pem(rsa)), "MESSAGE:", len(data), "DIGEST:", len(digest), "SIG:", len(sig), "ENC:", len(enc)
    
    # # smallest md5 (16 bytes)
    # bits = 16 * 8
    # rsa = rsa_generate_key(bits, 5)
    # digest = md5(data).digest()
    # sig = ""
    # enc = rsa.private_encrypt(digest, M2Crypto.RSA.no_padding)
    # print "BITS:", bits, "BYTES:", bits / 8, "PUBLIC-PEM:", len(rsa_to_public_pem(rsa)), "MESSAGE:", len(data), "DIGEST:", len(digest), "SIG:", len(sig), "ENC:", len(enc)

    # # record with md5 signature: users are identified by 20 bytes.
    # # the 16 byte signature is added, and the FROM USER is removed on
    # # the wire
    # from struct import pack
    # uid_length = 20
    # record = ("A" * uid_length) + ("B" * uid_length) + pack("!LLL", 0, 10, 2)
    # bits = 16 * 8
    # rsa = rsa_generate_key(bits, 5)
    # digest = md5(record).digest()
    # enc = record[uid_length:] + rsa.private_encrypt(digest, M2Crypto.RSA.no_padding)
    # print "BITS:", bits, "BYTES:", bits / 8, "PUBLIC-PEM:", len(rsa_to_public_pem(rsa)), "ENC:", len(enc)
    

    from struct import pack
    uid_length = 20
    record = ("A" * uid_length) + ("B" * uid_length) + pack("!LLL", 0, 10, 2)
    bits = 16 * 8
    rsa = rsa_generate_key(bits, 5)
    sig = rsa.private_encrypt(md5(record).digest(), M2Crypto.RSA.no_padding)
    record = ("A" * uid_length) + pack("!LLL", 0, 10, 2)
    msg = record + sig
    print "UID:", uid_length, "BITS:", bits, "PUBLIC-KEY:", len(rsa_to_public_bin(rsa)), "MESSAGE:", len(msg)

    from struct import pack
    uid_length = 5
    record = ("A" * uid_length) + ("B" * uid_length) + pack("!LLL", 0, 10, 2)
    bits = 16 * 8
    rsa = rsa_generate_key(bits, 5)
    # todo: sometimes crashes: M2Crypto.RSA.RSAError: data too large for modulus
    sig = rsa.private_encrypt(md5(record).digest(), M2Crypto.RSA.no_padding)
    record = ("A" * uid_length) + pack("!LLL", 0, 10, 2)
    msg = record + sig
    print "UID:", uid_length, "BITS:", bits, "PUBLIC-KEY:", len(rsa_to_public_bin(rsa)), "MESSAGE:", len(msg)

    from struct import pack
    uid_length = 4
    record = ("A" * uid_length) + ("B" * uid_length) + pack("!LLL", 0, 10, 2)
    bits = 16 * 8
    rsa = rsa_generate_key(bits, 5)
    sig = rsa.private_encrypt(md5(record).digest(), M2Crypto.RSA.no_padding)
    record = ("A" * uid_length) + pack("!LLL", 0, 10, 2)
    msg = record + sig
    print "UID:", uid_length, "BITS:", bits, "PUBLIC-KEY:", len(rsa_to_public_bin(rsa)), "MESSAGE:", len(msg)

    # encrypted record: users are identified by 20 bytes.  this
    # results in a 416 bits rsa key
    uid_length = 20
    record = ("A" * uid_length) + ("B" * uid_length) + pack("!LLL", 0, 10, 2)
    bits = len(record) * 8
    rsa = rsa_generate_key(bits, 5)
    enc = rsa.private_encrypt(record, M2Crypto.RSA.no_padding)
    msg = ("A" * uid_length) + enc
    print "UID:", uid_length, "BITS:", bits, "PUBLIC-KEY:", len(rsa_to_public_bin(rsa)), "MESSAGE:", len(msg)
    
    # encrypted record: users are identified by 4 bytes.  this results
    # in a 160 bits rsa key
    uid_length = 5
    record = ("A" * uid_length) + ("B" * uid_length) + pack("!LLL", 0, 10, 2)
    bits = len(record) * 8
    rsa = rsa_generate_key(bits, 5)
    enc = rsa.private_encrypt(record, M2Crypto.RSA.no_padding)
    msg = ("A" * uid_length) + enc
    print "UID:", uid_length, "BITS:", bits, "PUBLIC-KEY:", len(rsa_to_public_bin(rsa)), "MESSAGE:", len(msg)

    # encrypted record: users are identified by 4 bytes.  this results
    # in a 160 bits rsa key
    uid_length = 4
    record = ("A" * uid_length) + ("B" * uid_length) + ("T" * 8) + ("U" * 4) + ("D" * 4)
    bits = len(record) * 8
    rsa = rsa_generate_key(bits, 5)
    enc = rsa.private_encrypt(record, M2Crypto.RSA.no_padding)
    msg = ("A" * uid_length) + enc
    print "UID:", uid_length, "BITS:", bits, "PUBLIC-KEY:", len(rsa_to_public_bin(rsa)), "MESSAGE:", len(msg)

    print

    #
    # EC
    #

    # def ec_to_private_bin(rsa, cipher="aes_128_cbc", password=None):
    #     pem = rsa_to_private_pem(rsa, cipher, password)
    #     lines = pem.split("\n")
    #     return "".join(lines[4:-2]).decode("BASE64")

    from M2Crypto import EC
    record = "A" * 20
    for attr in dir(EC):
        if attr.startswith("NID_"):
            nid = getattr(EC, attr)

            # ec = EC.gen_params(EC.NID_sect233k1)
            ec = EC.gen_params(nid)
            ec.gen_key()
            try:
                sig = ec.sign_dsa_asn1(record)
                print "SIG:", len(sig), "B64:", len(sig.encode("BASE64")), "NID:", attr
            except Exception as e:
                print "SIG: --", "NID:", attr, e
