import tkinter as tk
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
# ******************************************************** Start caesar_encrypt*****************************************************************

def custom_caesar_encrypt():
    plaintext = entry_text.get()
    key = int(entry_key.get())
    ciphertext = ""
    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isupper():
            ciphertext += chr((ord(char) + key - 65) % 26 + 65)
        elif char.islower():
            ciphertext += chr((ord(char) + key - 97) % 26 + 97)
        else:
            ciphertext += char
    result_label.config(text="Encrypted text: " + ciphertext)
# ******************************************************** End caesar_encrypt*****************************************************************
# ******************************************************** Start vigenere_encrypt*****************************************************************
def vigenere_encrypt():
    text = entry_text.get()
    key = entry_key.get()

    def get_key(text, key):
        new_key = key
        if len(text) > len(key):
            for i in range(len(text) - len(key)):
                new_key += key[i % len(key)]
        return new_key

    def encrypt_text(text, new_key):
        encrypted_text = ""
        for i in range(len(text)):
            encrypted_text += chr((ord(text[i]) + ord(new_key[i])) % 26 + 65)
        return encrypted_text

    new_key = get_key(text, key)
    encrypted_text = encrypt_text(text, new_key)
    result_label.config(text="Encrypted text: " + encrypted_text)


# ******************************************************** End vigenere_encrypt*****************************************************************
# ******************************************************** Start hill_cipher_encrypt*****************************************************************

def hill_cipher_encrypt():
    plain_text = entry_text.get()
    key = entry_key.get()
    cipher_text = hill_cipher(plain_text, key)
    result_label.config(text="Encrypted text: " + cipher_text)

def hill_cipher(plain_text, key):
    key_length = len(key)
    square_size = int(key_length ** 0.5)

    # Convert the key string to a list of integers
    key_int = [ord(char) - 65 for char in key]

    # Generate key matrix from the provided key
    key_matrix = np.array(key_int).reshape(square_size, square_size)

    # Pad the plain text with 'X' if its length is not a multiple of the key matrix size
    if len(plain_text) % square_size != 0:
        plain_text += "X" * (square_size - len(plain_text) % square_size)

    cipher_text = ""
    for i in range(0, len(plain_text), square_size):
        # Convert a block of plain text to numerical values
        block = [ord(char) - 65 for char in plain_text[i:i + square_size]]

        # Perform matrix multiplication to encrypt the block
        encrypted_block = np.dot(key_matrix, block) % 26

        # Convert the encrypted block back to characters
        encrypted_chars = "".join([chr(value + 65) for value in encrypted_block])
        cipher_text += encrypted_chars

    return cipher_text
# ******************************************************** End hill_cipher_encrypt*****************************************************************
# ******************************************************** Start Playfair Encryption*****************************************************************

def convert_plaintext_to_digraphs(plaintext):
    # append X if Two letters are being repeated
    for s in range(0, len(plaintext) + 1, 2):
        if s < len(plaintext) - 1:
            if plaintext[s] == plaintext[s + 1]:
                plaintext = plaintext[:s + 1] + 'X' + plaintext[s + 1:]

    if len(plaintext) % 2 != 0:
        plaintext = plaintext[:] + 'X'

    return plaintext


def generate_key_matrix(key):
    matrix_5x5 = [[0 for i in range(5)] for j in range(5)]

    simple_key_array = []

    for c in key:
        if c == 'J':
            c = 'I'
        if c not in simple_key_array:
            simple_key_array.append(c)

    is_i_exist = "I" in simple_key_array

    for i in range(65, 91):
        
        if i == 74:
            i=73
            
        if chr(i) not in simple_key_array:
                simple_key_array.append(chr(i))

    index = 0
    for i in range(0, 5):
        for j in range(0, 5):
            matrix_5x5[i][j] = simple_key_array[index]
            index += 1

    return matrix_5x5


def index_locator(char, cipher_key_matrix):
    index_of_char = []

    if char == "J":
        char = "I"

    for i, j in enumerate(cipher_key_matrix):
        for k, l in enumerate(j):

            if char == l:
                index_of_char.append(i)
                index_of_char.append(k)
                return index_of_char


def playfair_cipher(plaintext, key):
    
    plaintext = convert_plaintext_to_digraphs(plaintext)
    key_matrix = generate_key_matrix(key)
    ciphertext = []

    i = 0
    while i < len(plaintext):
        n1 = index_locator(plaintext[i], key_matrix)
        n2 = index_locator(plaintext[i + 1], key_matrix)

        if n1[1] == n2[1]:
            i1 = (n1[0] + 1) % 5
            j1 = n1[1]

            i2 = (n2[0] + 1) % 5
            j2 = n2[1]

            ciphertext += key_matrix[i1][j1]
            ciphertext += key_matrix[i2][j2]

        elif n1[0] == n2[0]:
            i1 = n1[0]
            j1 = (n1[1] + 1) % 5

            i2 = n2[0]
            j2 = (n2[1] + 1) % 5

            ciphertext += key_matrix[i1][j1]
            ciphertext += key_matrix[i2][j2]

        else:
            i1 = n1[0]
            j1 = n1[1]

            i2 = n2[0]
            j2 = n2[1]

            ciphertext += key_matrix[i1][j2]
            ciphertext += key_matrix[i2][j1]

        i += 2

    return ciphertext

# ******************************************************** End Playfair Encryption*****************************************************************
# ******************************************************** Start AES Encryption*****************************************************************


# # Generate a random 256-bit AES key
# key = get_random_bytes(32)

# # Create an AES cipher object in CBC mode with automatic padding
# cipher = AES.new(key, AES.MODE_CBC)

# # Encrypt the plaintext
# plaintext = b'This is my secret message'
# padded_plaintext = pad(plaintext, AES.block_size)
# ciphertext = cipher.encrypt(padded_plaintext)

# print("Ciphertext:", ciphertext)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import tkinter as tk

def aes_encrypt():
    # Generate a random 256-bit AES key
    key = get_random_bytes(32)

    # Create an AES cipher object in CBC mode with automatic padding
    cipher = AES.new(key, AES.MODE_CBC)

    # Encrypt the plaintext
    plaintext = b'This is my secret message'
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    print("Ciphertext:", ciphertext)
    
aes_encrypt()  
# ******************************************************** End AES Encryption*****************************************************************




# ******************************************************** Start G U I   *****************************************************************

# Create the application window
window = tk.Tk()
window.title("Encryption Algorithms")
window.configure(bg="black")  # Set background color to black

# Create input fields and labels with padding
label_text = tk.Label(window, text="Text to Encrypt:", bg="black", fg="white")
label_text.grid(row=0, column=0, pady=10)
entry_text = tk.Entry(window)
entry_text.grid(row=0, column=1, pady=5)

label_key = tk.Label(window, text="Encryption Key:", bg="black", fg="white")
label_key.grid(row=1, column=0, pady=10)
entry_key = tk.Entry(window)
entry_key.grid(row=1, column=1, pady=5)

import tkinter as tk
import numpy as np


# Create the custom_caesar_encrypt button and set its color to red
encrypt_button = tk.Button(window, text="Caesar Encryption", command=custom_caesar_encrypt, bg="red")
encrypt_button.grid(row=2, column=0, columnspan=2, pady=10, padx=10)

# Create the vigenere_encrypt button
vigenere_cipher_button = tk.Button(window, text="Vigenere Encryption", command=vigenere_encrypt, bg="red")
vigenere_cipher_button.grid(row=3, column=0, columnspan=2, pady=10, padx=10)

# Create the Hill Cipher button
hill_cipher_button = tk.Button(window, text="Hill Encryption", command=hill_cipher_encrypt, bg="red")
hill_cipher_button.grid(row=4, column=0, pady=10, padx=10)

# Create the Playfair Cipher button
playfair_cipher_button = tk.Button(window, text="Playfair Encryption", command=playfair_cipher, bg="red")
playfair_cipher_button.grid(row=4, column=1, pady=10, padx=10)

# Create the AES Cipher button
AES_cipher_button = tk.Button(window, text="AES Encryption", command=aes_encrypt, bg="red")
AES_cipher_button.grid(row=5, column=0, columnspan=2,pady=10, padx=10)

# Create a label to display the result with padding
result_label = tk.Label(window, text="Encrypted text:", bg="green", fg="white")
result_label.grid(row=6, column=0, columnspan=2, pady=10)




window.mainloop()
