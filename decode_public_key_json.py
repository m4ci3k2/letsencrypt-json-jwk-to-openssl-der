""" Convert letsencrypt JSON-encoded RSA public key to OpenSSL compatible version

usage: python decode_public_key_json.py < regr.json > user.pub.der
       openssl rsa -pubin -inform DER -in user.pub.der -outform PEM -out user.pub.pem
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
    print('This script requires PyASN1 to function. Try running: pip install PyASN1')
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

    # convert bytes to hex string
    pub = binascii.hexlify(pub)

    # interpret hex string as integer
    return int(pub, 16)


class ModulusExponent(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('n', univ.Integer()),
        namedtype.NamedType('e', univ.Integer())
        )


class ObjectMetadata(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('object_id', univ.ObjectIdentifier()),
        namedtype.NamedType('null', univ.Null())
        )


class ObjectContainer(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('object_metadata', ObjectMetadata()),
        namedtype.NamedType('bits', univ.BitString())
        )


def make_der(public_key_json):
    pub_mod = decode_json_field(public_key_json['n'])
    pub_exp = decode_json_field(public_key_json['e'])

    object_metadata = ObjectMetadata()
    # 1.2.840.113549.1.1.1: RSA encryption
    object_metadata.setComponentByName('object_id', '1.2.840.113549.1.1.1')
    object_metadata.setComponentByName('null', '')

    mod_exp = ModulusExponent()
    mod_exp.setComponentByName('n', pub_mod)
    mod_exp.setComponentByName('e', pub_exp)
    bit_string_hex = "'" + binascii.hexlify(der_encoder.encode(mod_exp)) + "'H"
    bit_string = univ.BitString(bit_string_hex)

    object_container = ObjectContainer()
    object_container.setComponentByName('object_metadata', object_metadata)
    object_container.setComponentByName('bits', bit_string_hex)

    """
    Debug by printing human-readable hex
        print(binascii.hexlify(der_encoder.encode(object_container)))
    """
    return der_encoder.encode(object_container)


def main():
    json_obj = json.load(sys.stdin)
    public_key_json = json_obj['body']['key']
    encoded_der = make_der(public_key_json)
    sys.stdout.write(encoded_der)


if __name__ == '__main__':
    main()
