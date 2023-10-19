import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import math
import time
import matplotlib.pyplot as plt
print("..............AES ALGORITHM...............") 
password = input("Enter the AES key: ")
message = input("Enter the Message: ")
def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)
def unpad(text):
    return text[:-ord(text[-1])]
def encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    padded_plaintext_bytes = padded_plaintext.encode('utf-8')
    ciphertext = cipher.encrypt(padded_plaintext_bytes)
    return base64.b64encode(iv + ciphertext).decode('utf-8')
def decrypt(key, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)
    decrypted_text = unpad(decrypted_text.decode('utf-8'))

    return decrypted_text
print("................RSA ALGORITHM...................")
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def get_user_input_prime():
    while True:
        try:
            prime = int(input("Enter a prime number required to generate public and private keys: "))
            if is_prime(prime):
                return prime
            else:
                print("Please enter a valid prime number.")
        except ValueError:
            print("Please enter a valid integer.")

# Get user input for p and q
p = get_user_input_prime()
q = get_user_input_prime()
def find_coprime(num):
    value = 2 
    while True:
        if math.gcd(num, value) == 1:
            return value
        value += 1
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1
def generate_keypair(p, q):
    n = p * q 
    phi_n = (p - 1) * (q - 1)
    e = find_coprime(phi_n) 
    d = mod_inverse(e, phi_n)
    return (e, n),(d, n)
public_key, private_key = generate_keypair(p, q)
def encrypt1(public_key, plaintext):
    e,n=public_key
    return pow(plaintext, e, n)

def decrypt1(private_key, ciphertext):
    d,n=private_key
    return pow(ciphertext, d, n)

def sign(message, private_key):
    hash_value = hashlib.sha256(message.encode()).digest()
    print("The generated hash value from the message for digital signature:",hash_value)
    integer_value=int.from_bytes(hash_value, 'big')
    integer_value1=integer_value%private_key[1]
    print("The hash value which should be encrypted is:",integer_value1)
    signature1=encrypt1(private_key,integer_value1)
    print("The encrypted signature is:",signature1)
    return signature1

def verify(message, signature, public_key):
    hash_value = hashlib.sha256(message.encode()).digest()
    integer_value=int.from_bytes(hash_value, 'big')
    integer_value1=integer_value%private_key[1]
    computed_hash=decrypt1(public_key,signature)
    print("The decrypted signature is:",computed_hash)
    return integer_value1 == computed_hash
def encryption_time(encryption_time_aes,encryption_time_rsa):
    time=encryption_time_aes+encryption_time_rsa
    return time
def decryption_time(decryption_time_aes,decryption_time_rsa):
    time=decryption_time_aes+decryption_time_rsa
    return time
def plot_line_chart(labels,rsa_times,hybrid_times,title):
    plt.plot(labels, rsa_times, marker="o",label='RSA')
    plt.plot(labels, hybrid_times,marker="o",label='Hybrid (AES+RSA)')
    plt.xlabel('Message Length (bytes)')
    plt.ylabel('Time(s)')
    plt.title(title)
    plt.legend()
    plt.grid()
    plt.show()

def main():
    def convert_to_int(password):
        if password.isdigit():
            return int(password)
        else:
            concatenated_ascii = ''.join(str(ord(char)) for char in password)
            return concatenated_ascii
    password1=str(convert_to_int(password))
    key = PBKDF2(password1, b"salt", dkLen=32, count=1000000)
    public_key, private_key = generate_keypair(p,q)
    print("The public key in RSA is:",public_key)
    print("The private key in RSA is:",private_key)
    n=public_key[1]
    message1=int(password1)%n
    print("............The Encryption/Decryption process.............")
    while True:
        print("\nSelect an operation:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Authenticate User")
        print("4.Exit")
        choice = int(input("Enter your choice: "))
        if choice == 1:
             start_time=time.time()
             encrypted_message = encrypt(key, message)
             print("...........Encrypt the content using AES Algorithm...........")
             print("The encrypted Message:", encrypted_message)
             end_time=time.time()
             encryption_time_aes=end_time-start_time
             print("The encryption time for AES:",encryption_time_aes)
             start_time1=time.time()
             encrypted_password=encrypt1(public_key,message1)
             print("...........Encrypt the AES key using RSA Algorithm..............")
             print("The AES key is converted to integer for encryption:",message1)
             print("The encrypted AES key:",encrypted_password)
             end_time1=time.time()
             encryption_time_rsa=end_time1-start_time1
             print("The encryption time for RSA:",encryption_time_rsa)
             encrypt_time=encryption_time(encryption_time_aes,encryption_time_rsa)
             print("Hybrid Encryption time:",encrypt_time)
        elif choice == 2:
            start_time=time.time()
            decrypted_message = decrypt(key, encrypted_message)
            print("............Decrypt the content using AES Algorithm............")
            print("The decrypted content:", decrypted_message)
            end_time=time.time()
            decryption_time_aes=end_time-start_time
            print("The decryption time for AES:",decryption_time_aes)
            print("............Decrypt the AES key using RSA Algorithm............")
            start_time=time.time()
            decrypted_password=decrypt1(private_key,encrypted_password)
            print("The decrypted AES key:",decrypted_password)
            end_time=time.time()
            decryption_time_rsa=end_time-start_time
            print("The decryption time for RSA:",decryption_time_rsa)
            decrypt_time=decryption_time(decryption_time_aes,decryption_time_rsa)
            print("Hybrid Decryption time:",decrypt_time)
        elif choice == 3:
            print("............Authenticating the user using Digital Signature...........")
            signature=sign(message, private_key)
            is_valid = verify(message, signature, public_key)
            print("Is the signature valid?", is_valid)
        elif choice == 4:
            break
        else:
            print("Invalid choice. Please try again.")
    message_lengths = [128,256,512,1024,2048,5096]  # Message lengths in bytes
    rsa_times = [0.04,0.11,0.21,0.31,0.49,0.59]  # Placeholder RSA encryption times
    hybrid_times = [0.025,0.07,0.15,0.19,0.32,0.38]

    # Plot line chart for encryption times
    plot_line_chart(message_lengths,rsa_times, hybrid_times, 'Encryption')

    # Placeholder decryption times (modify these with actual times)
    rsa_dec_times = [0.60,0.86,1.31,1.76,2.68,3.2]
    hybrid_dec_times = [0.51,0.55,0.65,0.69,0.81,0.88]

    # Plot line chart for decryption times
    plot_line_chart(message_lengths,rsa_dec_times,hybrid_dec_times,'Decryption')

if __name__ == "__main__":
    main()

