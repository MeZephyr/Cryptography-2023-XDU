import Letter_frequencies as lf


cipherString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
# 先把16进制字符串转换成字节序列
ciphertext = bytes.fromhex(cipherString)
plaintext, key = lf.decipher(ciphertext)
plaintext = plaintext.decode("ASCII")
print(plaintext)
print(key)



