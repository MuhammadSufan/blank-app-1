import rsa
import os

# Function to generate RSA keys
def generate_keys():
    public_key, private_key = rsa.newkeys(512)  # 512-bit key for simplicity (use 2048 for better security)
    return public_key, private_key

# Function to encrypt a file
def encrypt_file(file_path, public_key):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = rsa.encrypt(file_data, public_key)
    return encrypted_data

# Function to decrypt a file
def decrypt_file(encrypted_data, private_key):
    try:
        decrypted_data = rsa.decrypt(encrypted_data, private_key)
        return decrypted_data
    except rsa.DecryptionError:
        return None

# Function to save the encrypted data to a file
def save_encrypted_data(encrypted_data, output_file):
    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

# Main function to run the encryption and decryption process
def main():
    print("Welcome to the RSA Encryption/Decryption Program")
    
    # 1. RSA Key Generation
    print("Generating RSA keys...")
    public_key, private_key = generate_keys()
    
    print("\nPublic Key: ", public_key)
    print("Private Key: ", private_key)
    
    # 2. File Encryption
    file_path = input("\nEnter the path of the .txt file to encrypt: ")
    
    if not os.path.exists(file_path):
        print("The file does not exist. Exiting.")
        return
    
    encrypted_data = encrypt_file(file_path, public_key)
    print("\nFile encrypted successfully.")
    
    encrypted_file_path = "encrypted_data.bin"
    save_encrypted_data(encrypted_data, encrypted_file_path)
    print(f"Encrypted file saved as {encrypted_file_path}")
    
    # 3. Decrypting the File
    print("\nNow, let's decrypt the file using the private key.")
    decrypted_data = decrypt_file(encrypted_data, private_key)
    
    if decrypted_data is None:
        print("Decryption failed: Incorrect private key.")
    else:
        print("\nDecrypted text:")
        print(decrypted_data.decode('utf-8'))
    
    # 4. Intrusion Detection: Decryption with an incorrect key
    print("\nAttempting decryption with an incorrect key...")
    wrong_private_key, _ = generate_keys()
    decrypted_data_with_wrong_key = decrypt_file(encrypted_data, wrong_private_key)
    
    if decrypted_data_with_wrong_key is None:
        print("Decryption with the wrong private key failed (as expected).")
    else:
        print("Decryption with the wrong key succeeded (unexpected).")
        
# Run the program
if __name__ == "__main__":
    main()
