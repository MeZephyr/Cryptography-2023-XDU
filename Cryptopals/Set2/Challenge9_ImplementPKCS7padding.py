def PKCS7_pad(plaintext: bytes, block_size: int) -> bytes:
    # 计算需要填充的字节
    padding_byte = block_size - len(plaintext) % block_size
    # 进行填充
    plaintext += padding_byte.to_bytes(1, "big") * padding_byte
    """
    to_bytes(x, "big") 是整数对象的一个方法，用于将整数表示为指定字节顺序的字节数组。
    参数解释：
    第一个参数 x 表示希望将整数转换为多少字节的字节数组。
    第二个参数 "big" 表示字节的顺序，这里是大端字节顺序（从高位到低位的顺序）。
    """
    return plaintext


def main():
    plaintext = "YELLOW SUBMARINE"
    block_size = 20
    plaintext_bytes = plaintext.encode()
    print(PKCS7_pad(plaintext_bytes, block_size))


if __name__ == "__main__":
    main()
