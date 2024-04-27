import tkinter as tk
from tkinter import ttk
import requests
import threading

def post_data(payload):
    """Function to post data to the API and fetch the response."""
    response = requests.post('http://127.0.0.1:5000/encrypt', data=payload)
    if response.status_code == 201:
        data = response.json()
        update_gui(f"Posted Successfully: {data}")
    else:
        update_gui("Failed to post data")

def update_gui(message):
    """Updates the GUI with information or data."""
    label.config(text=message)

def on_button_click():
    """Handler for button click that initiates data posting."""
    user_input = entry.get()
    payload = {'title': user_input, 'body': 'bar', 'userId': 1}
    threading.Thread(target=post_data, args=(payload,)).start()

# Create the main window
root = tk.Tk()
root.title("API Post Example")

# Add a text entry widget
entry = ttk.Entry(root, width=50)
entry.pack(pady=20)

# Add a label to display data or status
label = ttk.Label(root, text="Enter title and click the button to post data...")
label.pack(pady=10)

# Add a button to send data
button = ttk.Button(root, text="Post Data", command=on_button_click)
button.pack(pady=10)

# Start the Tkinter event loop
root.mainloop()
