from random import randint
from hashlib import sha1
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
    """
    assert isinstance(bits, (int, long))
    assert bits % 8 == 0
    assert isinstance(exponent, int)
    assert progress is None or callable(progress)
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

if __name__ == "__main__":
    bits = 1024
    exponent = 5
    rsa = rsa_generate_key(bits, exponent)
    public_pem = rsa_to_public_pem(rsa)
    private_pem = rsa_to_private_pem(rsa)

    print "Generating public / private key pair"
    print "Bits:", bits
    print "Exponent:", exponent
    print "SHA1(pub).HEX:", sha1(public_pem).digest().encode("HEX")
    print "SHA1(prv).HEX:", sha1(private_pem).digest().encode("HEX")
    print public_pem
    print private_pem

    data = "hello world"
    sig = rsa.sign(data)
    print len(data), "->", len(sig)
