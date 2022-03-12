import phe
import json
from phe import paillier # 開源庫
import keyCtrl
import time

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


# 讀檔
with open("phe_key.pub", "r") as F:
     pub_jwk = F.read()

with open("phe_key.priv", "r") as F:
     priv_jwk = F.read()

public_key, private_key = keypair_load_jwk(pub_jwk, priv_jwk)
print("pubkey:",public_key)

# 測試需要加密的數據
message_list = [3.1415926,100,-4.6e-12]
# 加密操作
time_start_enc = time.time()
encrypted_message_list = [public_key.encrypt(m) for m in message_list]
time_end_enc = time.time()
print("加密耗時ms：",time_end_enc-time_start_enc)
# 解密操作
time_start_dec = time.time()
decrypted_message_list = [private_key.decrypt(c) for c in encrypted_message_list]
time_end_dec = time.time()
print("解密耗時ms：",time_end_dec-time_start_dec)
# print(encrypted_message_list[0]) 
print("原始數據:",decrypted_message_list)

# 測試加法和乘法同態
a,b,c = encrypted_message_list # a,b,c分別為對應密文


print(encrypted_message_list)
print("a:",a)

a_sum = a + 5 # 密文加明文
a_sub = a - 3 # 密文加明文的相反數
b_mul = b * 1 # 密文乘明文,數乘
c_div = c / -10.0 # 密文乘明文的倒數

# print("a:",a.ciphertext()) # 密文a的純文本形式
# print("a_sum：",a_sum.ciphertext()) # 密文a_sum的純文本形式

print("a+5=",private_key.decrypt(a_sum))
print("a-3",private_key.decrypt(a_sub))
print("b*1=",private_key.decrypt(b_mul))
print("c/-10.0=",private_key.decrypt(c_div))

##密文加密文
print((private_key.decrypt(a)+private_key.decrypt(b))==private_key.decrypt(a+b)) 
print((private_key.decrypt(a)))
print((private_key.decrypt(b)))
print((private_key.decrypt(a+b)))