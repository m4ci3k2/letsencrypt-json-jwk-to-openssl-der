""" Convert letsencrypt JSON-encoded RSA private key to OpenSSL-compatible version

usage: python decode_private_key_json.py < private_key.json > user.key.der
       openssl rsa -inform DER -in user.key.der -outform PEM -out user.key.pem
"""

import base64
import binascii
import json
import struct
import sys

try:
    from pyasn1.codec.der import encoder as der_encoder
    from pyasn1.type import univ, namedtype, tag
    from rsa.asn1 import AsnPubKey
except ImportError:
    print('This script requires PyASN1 and rsa to function. Try running: pip install PyASN1 rsa')
    sys.exit(1)


def b64_add_missing_padding(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding > 0 and missing_padding < 4:
        data += '=' * missing_padding
    return data


def decode_json_field(field):
    pub_b64 = str(field)
    pub_b64 = b64_add_missing_padding(pub_b64)
    pub = base64.urlsafe_b64decode(pub_b64)
    pub = binascii.hexlify(pub)
    return int(pub, 16)


# see http://etherhack.co.uk/asymmetric/docs/rsa_key_breakdown.html for field order
class PrivateKeyContainer(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
        namedtype.NamedType('privateExponent', univ.Integer()),
        namedtype.NamedType('prime1', univ.Integer()),
        namedtype.NamedType('prime2', univ.Integer()),
        namedtype.NamedType('exponent1', univ.Integer()),
        namedtype.NamedType('exponent2', univ.Integer()),
        namedtype.NamedType('coefficient', univ.Integer())
        )


def make_der_from_rsa_private_key_json(json_obj):
    if json_obj['kty'] != 'RSA':
        raise TypeError('Invalid key type: must be RSA')

    # see https://tools.ietf.org/html/rfc3447 to help interpret these
    public_exponent = decode_json_field(json_obj['e'])
    private_exponent = decode_json_field(json_obj['d'])
    modulus = decode_json_field(json_obj['n'])
    prime1 = decode_json_field(json_obj['q'])
    prime2 = decode_json_field(json_obj['p'])
    coefficient = decode_json_field(json_obj['qi'])
    exponent1 = decode_json_field(json_obj['dp'])
    exponent2 = decode_json_field(json_obj['dq'])

    object_container = PrivateKeyContainer()
    object_container.setComponentByName('version', 0)
    object_container.setComponentByName('modulus', modulus)
    object_container.setComponentByName('publicExponent', public_exponent)
    object_container.setComponentByName('privateExponent', private_exponent)
    object_container.setComponentByName('prime1', prime1)
    object_container.setComponentByName('prime2', prime2)
    object_container.setComponentByName('exponent1', exponent1)
    object_container.setComponentByName('exponent2', exponent2)
    object_container.setComponentByName('coefficient', coefficient)

    """
    Debug by printing human-readable hex
        print(binascii.hexlify(der_encoder.encode(object_container)))

    compare to the output of
        openssl genrsa 4096 > sample.key.pem
        openssl rsa -inform PEM -in sample.key.pem -outform DER -out sample.key.der
        openssl asn1parse -inform DER -in sample.key.der
    """ 
    return der_encoder.encode(object_container)


def main():
    json_obj = json.load(sys.stdin)
    encoded_der = make_der_from_rsa_private_key_json(json_obj)
    sys.stdout.write(encoded_der)


if __name__ == '__main__':
    sys.exit(main())
