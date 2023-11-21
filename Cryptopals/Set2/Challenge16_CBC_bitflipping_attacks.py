from Cryptodome.Cipher import AES
import secrets
import re


def pad(value, size):
    if len(value) % size == 0:
        return value
    padding = size - len(value) % size
    padValue = bytes([padding]) * padding
    return value + padValue


class InvalidPaddingError(Exception):
    """无效PKCS#7填充的异常类
    """
    def __init__(self, paddedMsg, message="具有无效的PKCS#7填充。"):
        self.paddedMsg = paddedMsg
        self.message = message
        super().__init__(self.message)

    def __repr__(self):
        return f"{self.paddedMsg} {self.message}"


def valid_padding(paddedMsg, block_size):
    """检查`paddedMsg`是否具有给定`block_size`的有效PKCS#7填充
    """
    # 如果`paddedMsg`的长度不是`block_size`的倍数
    if len(paddedMsg) % block_size != 0:
        return False

    last_byte = paddedMsg[-1]

    # 如果last_byte的值大于或等于block_size
    if last_byte >= block_size:
        return False

    padValue = bytes([last_byte]) * last_byte
    # 如果所有填充字节不相同
    if paddedMsg[-last_byte:] != padValue:
        return False

    # 如果在去除填充后，剩余的字符不都是可打印字符
    if not paddedMsg[:-last_byte].decode('ascii').isprintable():
        return False

    return True


def remove_padding(paddedMsg, block_size):
    """从`paddedMsg`中去除填充，如果填充无效，则显示错误消息
    """
    if not valid_padding(paddedMsg, block_size):
        raise InvalidPaddingError

    last_byte = paddedMsg[-1]
    unpadded = paddedMsg[:-last_byte]
    return unpadded


# 这是替换的字典
QUOTE = {b';': b'%3B', b'=': b'%3D'}

KEY = secrets.token_bytes(AES.block_size)
IV = bytes(AES.block_size)  # 为了简单起见，只是一堆0's


def cbc_encrypt(input_text):
    """使用AES-128在CBC模式下加密`input_text`，
    在`input_text`中将`:`替换为`%3B`，将`=`替换为`%3D`
    """

    prepend = b"comment1=cooking%20MCs;userdata="
    append = b";comment2=%20like%20a%20pound%20of%20bacon"

    for key in QUOTE:
        input_text = re.sub(key, QUOTE[key], input_text)

    plaintext = prepend + input_text + append
    plaintext = pad(plaintext, AES.block_size)

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext


def check(ciphertext):
    """检查`ciphertext`解密后是否包含`;admin=true;`
    """

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)
    print(f"明文: {plaintext}")

    if b";admin=true;" in plaintext:
        return True

    return False


def test():
    """测试将`;admin=true;`注入到密文中
    """

    # 发送两个块的A
    input_string = b'A' * AES.block_size * 2
    ciphertext = cbc_encrypt(input_string)

    # 用`required`明文替换第一个块的A
    required = pad(b";admin=true;", AES.block_size)
    # 将所需文本的每个字节与第二个块即'A'的每个字节异或
    inject = bytes([r ^ ord('A') for r in required])

    # 额外 = 密文的长度 - 注入文本的长度 - 前缀的长度 = 一个输入块 + 后缀
    extra = len(ciphertext) - len(inject) - 2 * AES.block_size
    # 保持`inject`，填充两侧以与原始密文匹配长度与0异或不改变值
    # 这会用`required`替换输入的第一个块，而其余部分保持不变
    inject = bytes(2 * AES.block_size) + inject + bytes(extra)

    # 为了制作密文，将`inject`字节与密文的相应字节异或
    crafted = bytes([x ^ y for x, y in zip(ciphertext, inject)])

    if check(crafted):
        print("注入成功")
    else:
        print("注入失败")


if __name__ == "__main__":
    test()
