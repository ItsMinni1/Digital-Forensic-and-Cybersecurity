def decodeCaesar(cipherText):
    for shift in range(1, 26):
        decoded = []
        for char in cipherText:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted_char = chr((ord(char) - base - shift) % 26 + base)
                decoded.append(shifted_char)
            else:
                decoded.append(char)
        
        print(f"Shift {shift:2d}: {''.join(decoded)}")

cipher_text = input("Enter the ciphertext: ")
decodeCaesar(cipher_text)
