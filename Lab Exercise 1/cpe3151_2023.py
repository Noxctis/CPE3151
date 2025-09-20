import string
def is_printable(s):
    return all(c in string.printable for c in s)

def automated_crib_drag(cribs, cp1, cp2):
    xor_ciphers = ""
    for idx in range(len(cp1)):
        ic1 = cp1[idx]
        ic2 = cp2[idx]
        ic_xor = ic1 ^ ic2
        xor_ciphers += chr(ic_xor)

    for crib in cribs:
        print(f"\nCrib: '{crib}'")
        found = False
        for idx in range(len(xor_ciphers) - len(crib) + 1):
            slide = xor_ciphers[idx: idx + len(crib)]
            results = ""
            for i in range(len(crib)):
                ig = ord(crib[i])
                id = ord(slide[i])
                ir = ig ^ id
                results += chr(ir)
            if is_printable(results):
                # Show position, crib, and both plaintext fragments
                p1_fragment = crib
                p2_fragment = results
                print(f"Pos {idx}:\n  Crib in msg1: '{p1_fragment}'\n  Result in msg2: '{p2_fragment}'")
                found = True
        if not found:
            print("No readable results.")
import binascii

def crib_drag_attack(guess, cp1, cp2):
    xor_ciphers = ""
    for idx in range(len(cp1)):
        ic1 = cp1[idx]
        ic2 = cp2[idx]
        ic_xor = ic1 ^ ic2
        xor_ciphers += chr(ic_xor)
    # print(xor_ciphers.encode("ascii").hex())

    for idx in range(len(xor_ciphers) - len(guess) + 1):
        slide = xor_ciphers[idx: idx + len(guess)]
        results = ""
        for i in range(len(guess)):
            ig = ord(guess[i])
            id = ord(slide[i])
            ir = ig ^ id
            results += chr(ir)
        print(results)


def match_key(key, data):
    p_size = len(data)
    k_size = len(key)
    # print('P_SIZE: {} -- K_SIZE: {}'.format(p_size, k_size))
    if k_size < p_size:  # if key size is less than p_size, add character
        add_key = p_size - k_size
        for x in range(add_key):
            key = '{}{}'.format(key, key[x])
    else:
        key = '{}'.format(key[:p_size])
    # p_size = len(plaintext)
    # k_size = len(key)
    # print('NEW P_SIZE: {} -- K_SIZE: {}, KEY={}'.format(p_size, k_size, key))
    return key


def encrypt(key, plaintext):
    idx = 0  # Declare index (idx) variable

    key = match_key(key, plaintext)
    ciphertext = ""  # Declare ciphertext variable
    for p in plaintext:  # Take one character at a time in message
        ip = ord(p)  # Convert to Decimal value code
        k = key[idx]  # Take byte value of the key at idx
        ik = ord(k)  # Convert to Decimal value code
        inew = ip ^ ik  # XOR bit-by-bit
        ciphertext += chr(inew)  # Convert to character code and Update ciphertext
        print(p, hex(ip), k, hex(ik), hex(inew))  # print every result
        idx += 1  # Increment idx by 1
    # print("LENGTH CIPHERTEXT: {}".format(len(ciphertext)))
    hexstring = ciphertext.encode("ascii").hex()

    print("\nCheck here...")
    print("{}".format(plaintext, ciphertext))
    print("{}".format(ciphertext))
    print("{}".format(hexstring))

    return ciphertext


def decrypt(key, ciphertext):
    idx = 0  # Declare index (idx) variable
    key = match_key(key, ciphertext)
    plaintext = ""  # Declare plaintext variable
    for c in ciphertext:  # Take one character at a time in message
        ic = ord(c)  # Convert to Decimal value code
        k = key[idx]  # Take byte value of the key at idx
        ik = ord(k)  # Convert to Decimal value code
        inew = ic ^ ik  # XOR bit-by-bit
        plaintext += chr(inew)  # Convert to character code and Update ciphertext
        # print(c, hex(ic), k, hex(ik), hex(inew))  # print every result
        idx += 1  # Increment idx by 1

    print("\n{} --> {}\n".format(plaintext, plaintext.encode("ascii").hex()))
    return plaintext


if __name__ == '__main__':
    message1 = " "
    key = " "

    ciphertextHex1 = "21383653120a1e09540a110d0c1e330465475e15550603040610061c52030411161705540d0c08000a5d0e3d1b45070d061b1754180a140c1c2d156544595a11000e0350071106171a130655060111590a18041e4c"  # insert between " " the assigned ciphertext in hexstring format
    ciphertextHex2 = "2000041d0e430b0a014b131c1b0a631d3050591b112d004d1f1b114511120b4307170a111015094103125c170d095307160645040700181a16630029525250110a1b081d551600011a0106550601115907030e015d"  # insert between " " the assigned ciphertext in hexstring format

    # Convert the hexstring format to ascii string format. Insert script below.
    ciphertext1 = binascii.unhexlify(ciphertextHex1)
    ciphertext2 = binascii.unhexlify(ciphertextHex2)

    # Automated crib drag with parcel delivery related cribs
    cribs = [
        "parcel", "delivery", "package", "address", "courier", "ship", "track", "sender", "receiver", "express", "mail", "post", "service"
    ]
    automated_crib_drag(cribs, ciphertext1, ciphertext2)
