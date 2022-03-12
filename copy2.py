from phe import paillier # 開源庫
import time # 做性能測試

# 測試paillier參數
print("默認私鑰大小：",paillier.DEFAULT_KEYSIZE) #2048
# 生成公私鑰
public_key,private_key = paillier.generate_paillier_keypair()
print("public_key：",public_key)
#private_test1=PaillierPrivateKey(public_key, p, q)
print("private_key：",private_key)

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

#報錯，不支持a*b，因為通過密文加實現了明文加的目的，這和原理設計是不一致的，只支持密文加！
# print((private_key.decrypt(a)+private_key.decrypt(b))==private_key.decrypt(a*b)) 

