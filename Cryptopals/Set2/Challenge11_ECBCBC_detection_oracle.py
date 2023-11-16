import os
import random
from Challenge9_ImplementPKCS7padding import PKCS7_pad

from Cryptodome.Cipher import AES


# ECB加密
def AES_ECB_encrypt(plaintext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(PKCS7_pad(plaintext, AES.block_size))
    return ciphertext


# CBC加密
def AES_CBC_encrypt(plaintext: bytes, IV: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


# 将字节分块
def bytes_to_chunks(string: bytes, chunk_size: int):
    chunks = [string[i:i + chunk_size] for i in range(0, len(string), chunk_size)]
    return chunks


# 产生随机的指定长度的字节序列
def generate_random_bytes(key_length: int):
    # os.urandom(n)用于生成指定长度 n 的随机字节串。这个函数通常用于生成密码学上安全的随机数，例如用作加密密钥或初始化向量。
    return os.urandom(key_length)


def msg_pad(msg: bytes):
    # 左侧填充5-10个字节
    padded_msg = os.urandom(random.randint(5, 10))
    padded_msg += msg
    # 右侧填充5-10个字节
    padded_msg += os.urandom(random.randint(5, 10))

    # 填充字节后，需要再进行PKCS7填充
    if len(padded_msg) % AES.block_size:
        return PKCS7_pad(padded_msg, AES.block_size)
    else:
        return padded_msg


def encryption_oracle(msg: bytes):
    # 是否采用CBC模式
    CBC_mode = random.randint(0, 1)
    key = generate_random_bytes(16)
    padded_msg = msg_pad(msg)
    if CBC_mode:
        print("采用CBC加密")
        IV = generate_random_bytes(AES.block_size)
        ciphertext = AES_CBC_encrypt(padded_msg, IV, key)
    else:
        print("采用ECB加密")
        ciphertext = AES_ECB_encrypt(padded_msg, key)
    return ciphertext


# 甄别方法，看加密后的密文块是否有重复，有重复是ECB模式，否则是CBC模式
def detect_AES(ciphertext: bytes, chunk_size: int):
    chunks = bytes_to_chunks(ciphertext, chunk_size)
    # set 是一种无序、可变的集合数据类型，用于存储唯一的元素。
    unique_set = set(chunks)
    if len(unique_set) < len(chunks):
        return "检测为：ECB模式"
    else:
        return "检测为：CBC模式"


def main():
    msg = "Yellow SubmarineTwo One Nine TwoYellow Submarine"*2
    msg_bytes = msg.encode()
    # 重复多次，便于直观查看甄别效果
    for _ in range(10):
        print(detect_AES(encryption_oracle(msg_bytes), AES.block_size))
        print("--------------")


if __name__ == "__main__":
    main()
