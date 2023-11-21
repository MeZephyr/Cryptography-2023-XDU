import secrets
from base64 import b64decode
from Cryptodome.Cipher import AES
from random import Random as rand

UNKNOWN_STRING = b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = secrets.token_bytes(16)
prefix_length = rand().randint(1, 3 * AES.block_size)  # 可占用至多三个块（这是任意的）
PREFIX = secrets.token_bytes(prefix_length)


def pad(msg):
    """在`msg`前加上`your_string`，然后应用PKCS#7填充
    """
    paddedMsg = msg
    size = 16
    length = len(paddedMsg)
    if length % size == 0:
        return paddedMsg

    # 如果明文填充后的长度不是AES.BLOCK_SIZE的倍数，则进行PKCS#7填充
    padding = size - (length % size)
    padValue = bytes([padding])
    paddedMsg += padValue * padding

    return paddedMsg


def encryption_oracle(your_string):
    """使用AES-ECB-128加密`your_string` + msg` + `UNKNOWN_STRING`
    """
    msg = bytes('The unknown string given to you was:\n', 'ascii')
    # 将我们收到的`UNKNOWN_STRING`附加到`msg`，在其前置`your_string`，然后再加上`PREFIX`
    plaintext = PREFIX + your_string + msg + b64decode(UNKNOWN_STRING)
    # 对齐到正确的大小时应用`PKCS#7`填充
    paddedPlaintext = pad(plaintext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(paddedPlaintext)

    return ciphertext


def detect_block_size():
    """检测`encryption_oracle()`使用的`block_size`
    """
    feed = b"A"
    length = 0
    while True:
        cipher = encryption_oracle(feed)
        # 在每次迭代时，增加一个字符
        feed += feed
        # 如果密文的长度增加超过1，就必须添加PKCS#7填充以使明文的大小等于block_size
        # 增加的大小给出了block_size的值
        if not length == 0 and len(cipher) - length > 1:
            return len(cipher) - length
        length = len(cipher)


def detect_mode(cipher):
    """检测密码文本是使用ECB加密
    """
    chunkSize = 16
    chunks = []
    for i in range(0, len(cipher), chunkSize):
        chunks.append(cipher[i:i + chunkSize])

    uniqueChunks = set(chunks)
    if len(chunks) > len(uniqueChunks):
        return "ECB"
    return "not ECB"


def detect_prefix_length():
    # 检测在oracle中使用的前缀的长度

    block_size = detect_block_size()

    # 首先找到占用的整数块数
    test_case_1 = encryption_oracle(b'a')
    test_case_2 = encryption_oracle(b'b')

    length1 = len(test_case_1)
    length2 = len(test_case_2)

    blocks = 0
    min_length = min(length1, length2)
    # 如果任何一个块（从左边开始）是相同的，
    # 这些块由`PREFIX`占用
    for i in range(0, min_length, block_size):
        if test_case_1[i:i + block_size] != test_case_2[i:i + block_size]:
            break
        blocks += 1

    # 现在计算剩余的字节数并添加到总大小中
    test_input = b''
    length = blocks * block_size
    # 如果添加额外的`?`不会改变当前块的密文
    # 我们已经到达了该块的末尾，因此，
    # 我们找到了需要用一些前缀字符完成块的额外字符的数量
    for extra in range(block_size):
        test_input += b'?'
        curr = encryption_oracle(test_input)[length: length + block_size]
        next = encryption_oracle(test_input + b'?')[length: length + block_size]
        if curr == next:
            break

    residue = block_size - len(test_input)
    length += residue
    return length


def ecb_decrypt(block_size):
    """使用逐字节攻击（简单）解密明文（无需密钥）
    """
    # 常见字符=小写字母+大写字母+空格+数字
    # 以优化Brute-Force方法
    common = list(range(ord('a'), ord('z'))) + list(range(ord('A'), ord('Z'))) + [ord(' ')] + list(
        range(ord('0'), ord('9')))
    rare = [i for i in range(256) if i not in common]
    possibilities = bytes(common + rare)

    plaintext = b''  # 包含整个明文= `found_block`的总和
    check_length = block_size

    prefix_len = detect_prefix_length()
    print(f"计算出的前缀长度 = {prefix_len}")
    check_begin = (prefix_len // block_size) * block_size
    residue = prefix_len % block_size

    while True:
        # 随着在块中找到更多字符，要前置的A的数量减少
        prepend = b'A' * (block_size - 1 - (len(plaintext) + residue) % block_size)
        actual = encryption_oracle(prepend)[check_begin: check_begin + check_length]

        found = False
        for byte in possibilities:
            value = bytes([byte])
            your_string = prepend + plaintext + value
            produced = encryption_oracle(your_string)[check_begin: check_begin + check_length]
            if actual == produced:
                plaintext += value
                found = True
                break

        if not found:
            plaintext = PKCS7_trim(plaintext)
            print(f"明文: \n{plaintext.decode('ascii')}")
            return

        if (len(plaintext) + residue) % block_size == 0:
            check_length += block_size


def is_PKCS7_padded(text: bytes):
    # text[-x] 表示从字符串的末尾往前数第 x 个字符。
    # text[-x:] 表示从上述位置开始，取到字符串的末尾（包括第 x 个字符），形成一个子串。
    padding = text[-text[-1]:]
    for byte in padding:
        if not byte == text[-1]:
            return False
    return True


# 去除PKCS7填充
def PKCS7_trim(text: bytes):
    if is_PKCS7_padded(text):
        pad_length = text[-1]
        # text[:-x] 表示从字符串的开头取子串，直到倒数第 x 个字符之前（不包括倒数第 x 个字符）。
        return text[:-pad_length]
    else:
        return text


def main():
    # 检测块大小
    block_size = detect_block_size()
    print(f"块大小为 {block_size}")

    # 检测模式（应为ECB）
    repeated_plaintext = b"A" * 50
    cipher = encryption_oracle(repeated_plaintext)
    mode = detect_mode(cipher)
    print(f"加密模式为 {mode}")

    # 实际前缀长度
    print(f"实际前缀大小 = {len(PREFIX)}")

    # 解密`encryption_oracle()`中的明文
    ecb_decrypt(block_size)


if __name__ == "__main__":
    main()
