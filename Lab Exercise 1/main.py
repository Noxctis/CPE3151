def crib_drag_attack(guess, cp1, cp2):
    xor_ciphers = ""
    for idx in range(len(cp1)):
        ic1 = ord(cp1[idx])
        ic2 = ord(cp2[idx])
        ic_xor = ic1 ^ ic2
        xor_ciphers += chr(ic_xor)
    print(xor_ciphers.encode("ascii").hex())

    for idx in range(len(xor_ciphers) - len(guess)+1):
        slide = xor_ciphers[idx: idx + len(guess)]
        results = ""
        for i in range(len(guess)):
            ig = ord(guess[i])
            id = ord(slide[i])
            ir = ig ^ id
            results += chr(ir)
        print(results)


def encrypt(key, plaintext):
    idx = 0  # Declare index (idx) variable
    ciphertext = ""  # Declare ciphertext variable
    for p in plaintext:  # Take one character at a time in message
        ip = ord(p)  # Convert to Decimal value code
        k = key[idx]  # Take byte value of the key at idx
        ik = ord(k)  # Convert to Decimal value code
        inew = ip ^ ik  # XOR bit-by-bit
        ciphertext += chr(inew)  # Convert to character code and Update ciphertext
        print(p, hex(ip), k, hex(ik), hex(inew))  # print every result
        idx += 1  # Increment idx by 1

    print("\n{} --> {}\n".format(ciphertext, ciphertext.encode("ascii").hex()))
    return ciphertext


def decrypt(key, ciphertext):
    idx = 0  # Declare index (idx) variable
    plaintext = ""  # Declare plaintext variable
    for c in ciphertext:  # Take one character at a time in message
        ic = ord(c)  # Convert to Decimal value code
        k = key[idx]  # Take byte value of the key at idx
        ik = ord(k)  # Convert to Decimal value code
        inew = ic ^ ik  # XOR bit-by-bit
        plaintext += chr(inew)  # Convert to character code and Update ciphertext
        print(c, hex(ic), k, hex(ik), hex(inew))  # print every result
        idx += 1  # Increment idx by 1

    print("\n{} --> {}\n".format(plaintext, plaintext.encode("ascii").hex()))
    return plaintext


if __name__ == '__main__':
    message1 = "Hello world"
    message2 = "the program"

    key = "supersecret"

    ciphertext1 = encrypt(key, message1)
    plaintext1 = decrypt(key, ciphertext1)
    #
    ciphertext2 = encrypt(key, message2)
    plaintext1 = decrypt(key, ciphertext2)
    #
    guess = input("Guess a word: ")
    crib_drag_attack(guess, ciphertext1, ciphertext2)
