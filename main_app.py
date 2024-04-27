import tkinter as tk
from tkinter import filedialog
import requests
import os



enc_url = 'https://warm-garden-31732-ca8bf0395088.herokuapp.com/encrypt'
dec_url = 'https://warm-garden-31732-ca8bf0395088.herokuapp.com/decrypt'

def upload_encrypt():
    file_path = filedialog.askopenfilename(filetypes=[('.jpg', '.png')])
    if file_path:
        files = {'file': open(file_path, 'rb')}
        password = {'password': 'your_password'}  # You should manage passwords more securely
        response = requests.post(enc_url, files=files, data=password)
        if response.ok:
            # Assuming you want to save the encrypted file
            with open('encrypted_image.enc', 'wb') as f:
                f.write(response.content)
            result_label.config(text="Encryption successful, file saved as 'encrypted_image.enc'")
        else:
            result_label.config(text="Encryption failed: " + response.text)

def upload_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[('.enc',)])
    if file_path:
        files = {'file': open(file_path, 'rb')}
        password = {'password': 'your_password'}  # You should manage passwords more securely
        response = requests.post(dec_url, files=files, data=password)
        if response.ok:
            # Assuming you want to save the decrypted file
            with open('decrypted_image.jpg', 'wb') as f:
                f.write(response.content)
            result_label.config(text="Decryption successful, file saved as 'decrypted_image.jpg'")
        else:
            result_label.config(text="Decryption failed: " + response.text)

app = tk.Tk()
app.title('Encrypt/Decrypt API Client')

upload_encrypt_button = tk.Button(app, text="Upload and Encrypt File", command=upload_encrypt)
upload_encrypt_button.pack(pady=10)

upload_decrypt_button = tk.Button(app, text="Upload and Decrypt File", command=upload_decrypt)
upload_decrypt_button.pack(pady=10)

result_label = tk.Label(app, text="")
result_label.pack(pady=10)

app.mainloop()
