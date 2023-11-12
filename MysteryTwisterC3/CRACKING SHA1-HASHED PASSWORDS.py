# -*- coding: utf-8 -*-
import hashlib
from itertools import product
import time

TARGET_VALUE = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"
WORD_LIST = ['q', 'Q', 'w', 'W', 'n', 'N', 'i', 'I', '+', '*', '5', '%', '8', '(', '0', '=']


def generate_combinations(word_list, length):
    return (''.join(combination) for combination in product(word_list, repeat=7))


def find_matching_combination(target_value, word_list, length):
    for combination in generate_combinations(word_list, length):
        sha1_value = hashlib.sha1(bytearray(combination, 'utf-8')).hexdigest()
        if sha1_value == target_value:
            print(f"Matching key: {combination}")
            return True
    return False


def main():
    start_time = time.time()
    start_key_length = 8
    result = find_matching_combination(TARGET_VALUE, WORD_LIST, start_key_length)
    while not result:
        start_key_length += 1
        result = find_matching_combination(TARGET_VALUE, WORD_LIST, start_key_length)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time: {elapsed_time:.2f} seconds")


if __name__ == "__main__":
    main()
