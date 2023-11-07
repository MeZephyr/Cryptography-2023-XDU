from base64 import b64encode

hex_string1 = "1c0111001f010100061a024b53535009181c"
hex_string2 = "686974207468652062756c6c277320657965"
target_string = "746865206b696420646f6e277420706c6179"

# 转换成字节序列
byte_seq1 = bytes.fromhex(hex_string1)
byte_seq2 = bytes.fromhex(hex_string2)


def xor_bytes(seq1, seq2):
    # zip(seq1, seq2)将各个比特对应，然后for循环进行每个比特的异或
    ciphertext = b''.join([bytes(b1 ^ b2 for b1, b2 in zip(seq1, seq2))])
    return ciphertext


# 上面的函数返回的是字节序列，我们还需要将其转化为16进制字符串
result = xor_bytes(byte_seq1, byte_seq2).hex()
print(result == target_string)
