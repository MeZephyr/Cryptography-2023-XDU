import getKeyLength


# 将密文按照密钥长度进行分割组合
def split_bytes_by_modulo(input_bytes, key_len):
    result_bytes = [b""] * key_len  # 创建一个包含7个空字节串的列表
    for index, byte in enumerate(input_bytes):
        # 根据位置将字节分组
        group_index = index % key_len
        result_bytes[group_index] += bytes([byte])
    return result_bytes


# 判断异或结果是否为字母或标点或空格
def judge(x):
    return 65 <= x <= 90 or 97 <= x <= 122 or 32 <= x <= 33 or x == 39 or 44 <= x <= 46


# 获取密钥，基本原理是看异或结果是否完全是字母或标点或空格，不是则不对
def get_key(key_len: int, ciphertext_byte_chunks):
    key = []
    for i in range(key_len):
        length = len(ciphertext_byte_chunks[i])
        for k in range(256):
            for l in range(length):
                if not judge(ciphertext_byte_chunks[i][l] ^ k):
                    break
                if l == length - 1:
                    key.append(k)

    return key


# 来自Cryptopals set1 challenge6，用于解出明文
def repeating_xor(text: bytes, key) -> bytes:
    # 明文长度除以密钥长度，得到商和余数，便于扩展密钥长度
    quotient, remainder = divmod(len(text), len(key))
    key_extend = bytes(key * quotient + key[:remainder])
    # 逐个字节异或
    return bytes([x ^ y for x, y in zip(text, key_extend)])


key_length = 7
ciphertext_byte_chunk = split_bytes_by_modulo(getKeyLength.ciphertext_bytes, key_length)
final_key = get_key(key_length, ciphertext_byte_chunk)
plaintext = repeating_xor(getKeyLength.ciphertext_bytes, final_key)
print(plaintext.decode())
print(final_key)
