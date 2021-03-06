# import additional stuff needed later on:
import json

# import Paillier library
import phe
from phe import paillier # 開源庫

"""
args: public_key, private_key
return:jwk format json
"""
def keypair_dump_jwk(pub, priv, date=None):
    """Serializer for public-private keypair, to JWK format."""
    from datetime import datetime
    if date is None:
        date = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

    rec_pub = {
        'kty': 'DAJ',
        'alg': 'PAI-GN1',
        'key_ops': ['encrypt'],
        'n': phe.util.int_to_base64(pub.n),
        'kid': 'Paillier public key generated by phe on {}'.format(date)
    }

    rec_priv = {
        'kty': 'DAJ',
        'key_ops': ['decrypt'],
        'p': phe.util.int_to_base64(priv.p),
        'q': phe.util.int_to_base64(priv.q),
        'kid': 'Paillier private key generated by phe on {}'.format(date)
    }

    priv_jwk = json.dumps(rec_priv)
    pub_jwk = json.dumps(rec_pub)
    return pub_jwk, priv_jwk


def keypair_load_jwk(pub_jwk, priv_jwk):
    """Deserializer for public-private keypair, from JWK format."""
    rec_pub = json.loads(pub_jwk)
    rec_priv = json.loads(priv_jwk)
    # Do some basic checks                                                                                                                                                      
    assert rec_pub['kty'] == "DAJ", "Invalid public key type"
    assert rec_pub['alg'] == "PAI-GN1", "Invalid public key algorithm"
    assert rec_priv['kty'] == "DAJ", "Invalid private key type"
    pub_n = phe.util.base64_to_int(rec_pub['n'])
    pub = paillier.PaillierPublicKey(pub_n)
    priv_p = phe.util.base64_to_int(rec_priv['p'])
    priv_q = phe.util.base64_to_int(rec_priv['q'])
    priv = paillier.PaillierPrivateKey(pub, priv_p, priv_q)
    return pub, priv