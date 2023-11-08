from base64 import b64decode
import Challenge3_SingleByteXor as lf
from Challenge5_repeatingXor import repeating_xor

with open('6.txt', 'r') as file:
    data = file.read()

decoded_data = b64decode(data)


# 汉明距离：在信息论中，两个等长字符串之间的汉明距离是两个字符串对应位置的不同字符的个数。
# 换句话说，它就是将一个字符串变换成另外一个字符串所需要替换的字符个数。
# 在计算机里，两个字节序列的汉明距离则只需考虑0和1
# 因此，我们只需要将两个字节序列逐个字节异或，并统计全部异或结果中”1“的个数即可
# ”1“的个数就是汉明距离
def hamming_distance(x: bytes, y: bytes):
    assert len(x) == len(y)
    distance = 0
    for byte1, byte2 in zip(x, y):
        xor_result = byte1 ^ byte2
        distance += bin(xor_result).count('1')
    return distance


# 着手点是密钥长度。
# 当我们把密文按照密钥长度去划分为等长的，那么，由于明文都是字母、空格、标点等，都在ASCII编码中，他们的汉明距离会较小；
# 因此，我们可以使用暴力破解的方法，遍历密钥长度，汉明距离最小的最有可能是密钥长度
# 在这里，将汉明距离归一化是必要的，因为这样才能在不同长度密钥下比较
def get_keySize(ciphertext: bytes):
    keySize = None
    min_distance = None
    for keyLength in range(2, 41):
        edit_distance = 0
        # 在这里，每个密钥长度，我们取了4组求平均的汉明距离。
        chunks = [ciphertext[i * keyLength:(i + 1) * keyLength] for i in range(4)]
        for i in range(0, len(chunks)):
            for j in range(0, len(chunks)):
                edit_distance += hamming_distance(chunks[i], chunks[j])
        # 归一化处理
        normalized_distance = edit_distance / keyLength

        if min_distance is None or normalized_distance < min_distance:
            min_distance = normalized_distance
            keySize = keyLength
    return keySize


# 根据密钥大小分块，便于后续得出密钥
keySize = get_keySize(decoded_data)
cipherChunks = [decoded_data[i:i + keySize] for i in range(0, len(decoded_data), keySize)]
# 为了保持每个块长度一致，我们可以去掉最后一块，这没有影响
cipherChunks.pop()
num_of_chunks = len(cipherChunks)
# 解出密钥
key = ""
for i in range(keySize):
    ciphertext = ""
    for j in range(num_of_chunks):
        # cipherChunks实际上是块长为keySize的数组，其中的元素是字节序列，
        # 当我们用cipherChunks[j][i]去访问时，涉及到一个强制类型转换，，一个字节变成了int类型的ASCII值
        ciphertext += chr(cipherChunks[j][i])
    ciphertext = ciphertext.encode()
    plaintext, key_letter = lf.decipher(ciphertext)
    key += chr(key_letter)
byte_key = key.encode()

# 解密
plaintext = repeating_xor(decoded_data, byte_key)
print(plaintext.decode())
