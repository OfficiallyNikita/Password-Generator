import random
import string
import hashlib

# Algorithm 1: Basic Random Password Generator
def basic_random_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Algorithm 2: Password from Cryptographic Hash (SHA-256) ( It creates a unique, irreversible hash of a password)
def hash_based_password(seed):
    return hashlib.sha256(seed.encode()).hexdigest()

# Algorithm 3: Markov Chain Password Generator (Simple Implementation)
def markov_chain_password(length):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Algorithm 4: High Entropy Password
def high_entropy_password(length):
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))

# Encryption and Decryption (for simple demonstration)
def encrypt_password(password, key):
    encrypted = ''.join(chr(ord(char) + key) for char in password)
    return encrypted

def decrypt_password(encrypted_password, key):
    decrypted = ''.join(chr(ord(char) - key) for char in encrypted_password)
    return decrypted

# Main Function for User Interaction
def main():
    print("Welcome to the Password Generator and Encryption Tool")
    print("Please choose an option:")
    print("1. Generate Basic Random Password")
    print("2. Generate Hash-based Password (SHA-256)")
    print("3. Generate Markov Chain Password")
    print("4. Generate High Entropy Password")
    
    choice = input("Enter your choice (1/2/3/4): ")

    if choice == '1':
        length = int(input("Enter the desired length of the password: "))
        password = basic_random_password(length)
        print(f"Generated Basic Random Password: {password}")
    
    elif choice == '2':
        seed = input("Enter a seed (e.g., user input) for the hash: ")
        password = hash_based_password(seed)
        print(f"Generated Hash-based Password (SHA-256): {password}")

    elif choice == '3':
        length = int(input("Enter the desired length of the password: "))
        password = markov_chain_password(length)
        print(f"Generated Markov Chain Password: {password}")
    
    elif choice == '4':
        length = int(input("Enter the desired length of the password: "))
        password = high_entropy_password(length)
        print(f"Generated High Entropy Password: {password}")
    
    else:
        print("Invalid choice! Please restart and choose a valid option.")
        return
    
    # Asking user if they want to encrypt/decrypt the password
    print("\nWould you like to encrypt or decrypt the password?")
    print("1. Encrypt Password")
    print("2. Decrypt Password")
    encrypt_choice = input("Enter your choice (1/2) or press Enter to skip: ")
    
    if encrypt_choice == '1':
        key = int(input("Enter a numeric key for encryption (e.g., 3): "))
        encrypted_password = encrypt_password(password, key)
        print(f"Encrypted Password: {encrypted_password}")
    
    elif encrypt_choice == '2':
        encrypted_password = input("Enter the encrypted password: ")
        key = int(input("Enter the numeric key used for encryption: "))
        decrypted_password = decrypt_password(encrypted_password, key)
        print(f"Decrypted Password: {decrypted_password}")
    
    else:
        print("Skipping encryption/decryption process.")

if __name__ == "__main__":
    main()


#How to Use:
# 1.The user selects one of the four algorithms to generate a password.
# 2.The program asks for the length of the password or a seed (depending on the algorithm).
# 3.The generated password is displayed.
# 4.The user is prompted to either encrypt or decrypt the password.

#For encryption, the user enters a numeric key, and the password is encrypted.
#For decryption, the user enters the encrypted password and the key used for encryption, and the original password is restored.'''