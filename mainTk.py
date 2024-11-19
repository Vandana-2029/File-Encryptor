import tkinter as tk
from tkinter import filedialog, messagebox
import os

def encrypt_file_inplace(input_file_path, output_file_path, password):
    """
    Encrypts the content of the file using an 8-byte password
    and overwrites the file with the encrypted content.

    :param input_file_path: Path to the file to be encrypted
    :param output_file_path: Output file path
    :param password: Password for encryption (up to 8 bytes)
    """
    if len(password) > 8:
        raise ValueError("Password must be 8 bytes or less.")
    
    # Pad the password to 8 bytes if it's shorter
    password_bytes = password.encode('utf-8').ljust(8, b'\0')

    try:
        # Read the original file content
        with open(input_file_path, 'rb') as file:
            data = file.read()

        # Encrypt the content in memory
        encrypted_data = bytearray()
        for i in range(0, len(data), 8):
            chunk = data[i:i+8]  # Take 8-byte chunk
            encrypted_block = bytes([b ^ p for b, p in zip(chunk, password_bytes)])
            encrypted_data.extend(encrypted_block)

        # Write the encrypted content to the output file
        with open(output_file_path, 'wb') as file:
            file.write(encrypted_data)

        messagebox.showinfo("Success", f"File encrypted successfully and saved as {output_file_path}")
    except FileNotFoundError:
        messagebox.showerror("Error", f"File '{input_file_path}' not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


# GUI
def browse_input_file():
    input_file = filedialog.askopenfilename(title="Select Input File")
    input_file_var.set(input_file)

def browse_output_file():
    output_file = filedialog.asksaveasfilename(title="Select Output File", defaultextension=".enc")
    output_file_var.set(output_file)

def encrypt_file():
    input_file_path = input_file_var.get()
    output_file_path = output_file_var.get()
    password = password_var.get()

    if not input_file_path or not os.path.isfile(input_file_path):
        messagebox.showerror("Error", "Please select a valid input file.")
        return
    if not output_file_path:
        messagebox.showerror("Error", "Please select an output file path.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        encrypt_file_inplace(input_file_path, output_file_path, password)
    except ValueError as e:
        messagebox.showerror("Error", str(e))


# Create the main window
root = tk.Tk()
root.title("File Encryptor")
root.geometry("500x300")

# Input file
tk.Label(root, text="Input File:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
input_file_var = tk.StringVar()
tk.Entry(root, textvariable=input_file_var, width=40).grid(row=0, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=browse_input_file).grid(row=0, column=2, padx=10, pady=10)

# Output file
tk.Label(root, text="Output File:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
output_file_var = tk.StringVar()
tk.Entry(root, textvariable=output_file_var, width=40).grid(row=1, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=browse_output_file).grid(row=1, column=2, padx=10, pady=10)

# Password
tk.Label(root, text="Password:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
password_var = tk.StringVar()
tk.Entry(root, textvariable=password_var, show="*", width=40).grid(row=2, column=1, padx=10, pady=10)

# Encrypt button
tk.Button(root, text="Encrypt File", command=encrypt_file, width=15).grid(row=3, column=1, pady=20)

# Run the main loop
root.mainloop()
