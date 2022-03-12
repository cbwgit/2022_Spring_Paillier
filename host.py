from xml.sax.handler import property_interning_dict
from phe import paillier # 開源庫
import keyCtrl
# import time # 做性能測試

# 測試paillier參數
print("默認私鑰大小：",paillier.DEFAULT_KEYSIZE) #2048
# 生成公私鑰
public_key,private_key = paillier.generate_paillier_keypair()
print("public_key：",public_key)
print("private_key：",private_key)
print("=================save key========================")
pub_jwk, priv_jwk = keyCtrl.keypair_dump_jwk(public_key, private_key)

# 存檔 公鑰
with open("phe_key.pub", "w") as F:
    F.write(pub_jwk + "\n")
    print("Written public key to {}".format(F.name))
    print("n={}".format(public_key.n))

# 存檔 私鑰
with open("phe_key.priv", "w") as F:
    F.write(priv_jwk + "\n")
    print("Written public key to {}".format(F.name))
    # print("n={}".format(private_key.n))

