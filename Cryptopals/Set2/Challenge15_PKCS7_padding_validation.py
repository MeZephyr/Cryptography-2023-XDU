def valid_padding(paddedMsg, block_size):
    # 检查`paddedMsg`是否具有给定`block_size`的有效PKCS#7填充

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
    # 从`paddedMsg`中去除填充，如果填充无效，则显示错误消息

    try:
        if not valid_padding(paddedMsg, block_size):
            raise ValueError
    except ValueError:
        print(f"{paddedMsg} 具有无效的PKCS#7填充。")
        return

    last_byte = paddedMsg[-1]
    unpadded = paddedMsg[:-last_byte]
    print(f"成功去除填充...")
    print(f"在去除填充之前: {paddedMsg}")
    print(f"在去除填充之后: {unpadded}")


def test():
    """为各种测试案例测试`remove_padding()`函数。
    """

    block_size = 16

    # 测试案例1: 不正确的值 < 所需值:
    paddedMsg = b'ICE ICE BABY\x03\x03\x03\x03'
    remove_padding(paddedMsg, block_size)

    # 测试案例2: 不正确的值 > 所需值:
    paddedMsg = b"ICE ICE BABY\x05\x05\x05\x05"
    remove_padding(paddedMsg, block_size)

    # 测试案例3: 不正确的长度:
    paddedMsg = b"ICE ICE BABY\x04\x04\x04"
    remove_padding(paddedMsg, block_size)

    # 测试案例4: 变量数量:
    paddedMsg = b"ICE ICE BABY\x01\x02\x03\x04"
    remove_padding(paddedMsg, block_size)

    # 测试案例5: 正确的填充
    paddedMsg = b"ICE ICE BABY\x04\x04\x04\x04"
    remove_padding(paddedMsg, block_size)


if __name__ == "__main__":
    test()
