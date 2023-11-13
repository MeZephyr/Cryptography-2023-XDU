import base64
from Cryptodome.Cipher import AES


# 判断有没有使用PKCS#7填充，原理是取与最后一个字节的值的相应长度的字节，看这些字节是否相同
def is_PKCS7_padded(text: bytes):
    # text[-x] 表示从字符串的末尾往前数第 x 个字符。
    # text[-x:] 表示从上述位置开始，取到字符串的末尾（包括第 x 个字符），形成一个子串。
    padding = text[-text[-1]:]
    for byte in padding:
        if not byte == text[-1]:
            return False
    return True


# 删除填充的部分
# 判断有没有填充，没有则返回原字节序列，否则返回删除掉最后长度为最后一个字节值的字节序列
def PKCS7_trim(text: bytes):
    if is_PKCS7_padded(text):
        pad_length = text[-1]
        # text[:-x] 表示从字符串的开头取子串，直到倒数第 x 个字符之前（不包括倒数第 x 个字符）。
        return text[:-pad_length]
    else:
        return text


# ECB解密
def AES_ECB_decrypt(ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return PKCS7_trim(cipher.decrypt(ciphertext))


# CBC解密
def AES_CBC_decrypt(ciphertext: bytes, IV: bytes, key: bytes):
    previous = IV
    key_length = len(key)
    plaintext = b''
    # 将密文按照密钥长度分块
    for i in range(0, len(ciphertext), key_length):
        # 解密运算其实是ECB的解密
        cipher = AES_ECB_decrypt(ciphertext[i:i + key_length], key)
        # 前一个密文与后一个解密运算进行异或
        xor_list = [chr(b1 ^ b2) for b1, b2 in zip(cipher, previous)]
        plaintext += "".join(xor_list).encode()
        previous = ciphertext[i:i + key_length]
    return plaintext


def main():
    # 文件经过处理，已经将原文件中的换行符删除
    with open("10.txt", "r") as file:
        b64_data = file.read()
    key = b"YELLOW SUBMARINE"
    ciphertext_bytes = base64.b64decode(b64_data)
    # 删除掉填充
    text = PKCS7_trim(AES_CBC_decrypt(ciphertext_bytes, b'\x00' * AES.block_size, key))
    print(text.decode("utf-8"))


if __name__ == "__main__":
    main()
