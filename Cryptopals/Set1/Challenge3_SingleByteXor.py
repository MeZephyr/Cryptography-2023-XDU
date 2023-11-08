from collections import Counter

character_frequencies = {
    # 字母频率表数据来源：维基百科
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253,
    'e': 12.702, 'f': 2.228, 'g': 2.015, 'h': 6.094,
    'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
    'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929,
    'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
    'y': 1.974, 'z': 0.074
}

dist = list(character_frequencies.values())


def compute_fitting_index(string: bytes) -> float:
    # Counter对象
    counter = Counter(string)
    dist_text = [
        # ord 获取字符的ASCII值
        (counter[ord(letter)] * 100) / len(string)
        for letter in character_frequencies
    ]
    return sum([abs(n - m) for n, m in zip(dist, dist_text)]) / len(dist_text)


# 逐字节异或，python的异或有整数之间的按位异或，有布尔值的异或，有逐字节的异或，没有bit级别的异或
def single_byte_xor(string: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in string])


def decipher(ciphertext: bytes):
    key = None
    plaintext = None
    min_index = 99999
    for k in range(256):
        # 逻辑是每个字节与密文异或，取拟合程度最高的
        candidate_plaintext = single_byte_xor(ciphertext, k)
        fitting_index = compute_fitting_index(candidate_plaintext)
        if fitting_index < min_index:
            key, plaintext, min_index = k, candidate_plaintext, fitting_index
    return plaintext, key


if __name__ == "__main__":
    cipherString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    # 先把16进制字符串转换成字节序列
    ciphertext = bytes.fromhex(cipherString)
    plaintext, key = decipher(ciphertext)
    plaintext = plaintext.decode("ASCII")
    print(plaintext)
    print(key)



