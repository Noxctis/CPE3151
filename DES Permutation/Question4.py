def solve_permutation():
    # 1. INPUT: The Original 64-bit Key (Table II)
    # Enter the rows exactly as they appear in the grid (0s and 1s)
    key_rows = [
        "00010011", # Row 0
        "00110100", # Row 8
        "01010111", # Row 16
        "01111001", # Row 24
        "10011011", # Row 32
        "10111100", # Row 40
        "11011111", # Row 48
        "11110001"  # Row 56
    ]
    
    # Flatten into a single string (1-based indexing logic handled below)
    original_key_bits = "".join(key_rows) 

    # 2. INPUT: The Permutation Table (Table I)
    # Just list the numbers row by row
    perm_table = [
        57, 49, 41, 33, 25, 17, 9, 8,
        1,  58, 50, 42, 34, 26, 18, 16,
        10, 2,  59, 51, 43, 35, 27, 24,
        19, 11, 3,  60, 52, 44, 36, 32,
        63, 55, 47, 39, 31, 23, 15, 40,
        7,  62, 54, 46, 38, 30, 22, 48,
        14, 6,  61, 53, 45, 37, 29, 56,
        21, 13, 5,  28, 20, 12, 4,  64
    ]

    # 3. THE SOLVER
    result_bits = []
    for index in perm_table:
        # Tables use 1-based indexing, Python uses 0-based.
        # So we grab the bit at (index - 1)
        bit = original_key_bits[index - 1]
        result_bits.append(bit)

    # 4. FORMATTING (Add dashes every 8 bits)
    final_string = ""
    for i in range(0, len(result_bits), 8):
        byte = "".join(result_bits[i:i+8])
        final_string += byte + "-"
    
    # Remove trailing dash
    print("FINAL ANSWER:")
    print(final_string[:-1])

solve_permutation()