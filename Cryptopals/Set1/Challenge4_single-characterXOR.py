import Challenge3_SingleByteXor as lf


with open('4.txt', 'r') as file:
    data = file.read()

# 把每列数据读入，并转换为字节序列，存储在列表中
byte_string = []
for line in data.split():
    byte_line = bytes.fromhex(line)
    byte_string.append(byte_line)

# 选出每一行数据中，最有可能的解密出的明文，存储在新列表中，作为候选文本
candidate_plaintext_list = []
for line in byte_string:
    candidate_plaintext, candidate_key = lf.decipher(line)
    candidate_plaintext_list.append(candidate_plaintext)

min_index = 99999
plaintext = None
# 从候选文本中选出拟合程度最好的明文
for line in candidate_plaintext_list:
    fitting_index = lf.compute_fitting_index(line)
    if fitting_index < min_index:
        plaintext, min_index = line, fitting_index
plaintext = plaintext.decode("ASCII")
print(plaintext)
