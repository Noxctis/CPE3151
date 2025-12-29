def solve_question_6():
    # 1. INPUT: Table I (Plaintext) - Enter the 4 rows of 0s and 1s
    plaintext_rows = [
        "0000000100100011", # Row 0 (Bits 1-16)
        "0100010101100111", # Row 1 (Bits 17-32)
        "1000100110101011", # Row 2 (Bits 33-48)
        "1100110111101111"  # Row 3 (Bits 49-64)
    ]
    plaintext_bits = "".join(plaintext_rows)

    # 2. INPUT: Table II (Permutation) - The numbers from the grid
    perm_table = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 33, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]

    # 3. SOLVE
    result_bits = []
    for index in perm_table:
        result_bits.append(plaintext_bits[index - 1])

    # 4. FORMAT
    final_string = ""
    for i in range(0, len(result_bits), 8):
        final_string += "".join(result_bits[i:i+8]) + "-"
    
    print("ANSWER TO COPY:")
    print(final_string[:-1])

solve_question_6()