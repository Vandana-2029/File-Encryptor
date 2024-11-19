def encrypt_file_inplace(file_path, password):
    """
    Encrypts the content of the given file using an 8-byte password
    and saves the changes directly to the same file.

    :param file_path: Path to the file to be encrypted
    :param password: 8-byte password for encryption
    """
    if len(password) != 8:
        raise ValueError("Password must be exactly 8 bytes.")
    
    password_bytes = password.encode('utf-8')  # Convert password to bytes

    try:
        with open(file_path, 'rb+') as file:  # Open file for reading and writing in binary mode
            file_content = file.read()  # Read the entire content of the file

            # Process the content in 8-byte blocks
            encrypted_content = bytearray()
            for i in range(0, len(file_content), 8):
                chunk = file_content[i:i+8]
                
                # Pad the block to 8 bytes if it's shorter
                # if len(chunk) < 8:
                #     chunk = chunk.ljust(8, b'\0')
                
                # XOR the block with the password
                encrypted_block = bytes([b ^ p for b, p in zip(chunk, password_bytes)])
                encrypted_content.extend(encrypted_block)

            # Go back to the start of the file and overwrite it with encrypted content
            file.seek(0)
            file.write(encrypted_content)
            file.truncate()  # Ensure no leftover data remains

        print(f"File encrypted successfully in-place at {file_path}")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Example usage
if __name__ == "__main__":
    file_path = "Testing\\img2.png"  # Replace with the path to your file
    password = "password"           # Replace with your 8-byte password

    encrypt_file_inplace(file_path, password)
