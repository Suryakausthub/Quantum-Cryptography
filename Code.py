import tkinter as tk
from tkinter import ttk, messagebox
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import random
from scipy.stats import entropy
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx

# Function to generate random bitstrings
def random_bitstring(length):
    return np.random.choice(['0', '1'], size=length)

# BB84 Protocol with Visualization, Error Checking, and Eavesdropping Simulation
def bb84_protocol_visualized(alice_id, bob_id, length=8, error_rate=0.1, eavesdropping=False, update_step=None):
    alice_bits = random_bitstring(length)
    alice_bases = random_bitstring(length)
    bob_bases = random_bitstring(length)
    key = []
    simulator = AerSimulator()
    errors = 0
    error_rates = []  # Track error rates for each step
    entropy_values = []  # Track entropy at each step
    eavesdropped_bits = []  # Track bits altered due to eavesdropping

    for i in range(length):
        qc = QuantumCircuit(1, 1)
        if alice_bases[i] == '0':  # Z-basis
            if alice_bits[i] == '1':
                qc.x(0)
        else:  # X-basis
            if alice_bits[i] == '0':
                qc.h(0)
            else:
                qc.x(0)
                qc.h(0)

        if eavesdropping:
            # Simulate eavesdropping by measuring in a random basis
            eve_basis = random.choice(['0', '1'])
            if eve_basis == '1':
                qc.h(0)
            qc.measure(0, 0)
            compiled_circuit = transpile(qc, simulator)
            result = simulator.run(compiled_circuit).result()
            intercepted_bit = list(result.get_counts().keys())[0]
            qc.reset(0)
            if intercepted_bit == '1':
                qc.x(0)
            if eve_basis == '1':
                qc.h(0)
            # Record that eavesdropping occurred at this bit
            eavesdropped_bits.append(i)

        if bob_bases[i] == '1':
            qc.h(0)
        qc.measure(0, 0)

        compiled_circuit = transpile(qc, simulator)
        result = simulator.run(compiled_circuit).result()
        measured_bit = list(result.get_counts().keys())[0]

        # Introduce noise due to the error rate
        if random.random() < error_rate:
            measured_bit = '1' if measured_bit == '0' else '0'

        if alice_bases[i] == bob_bases[i]:
            key.append(measured_bit)
            if measured_bit != alice_bits[i]:
                errors += 1

        # Track error rate and entropy
        error_rate_step = errors / (i + 1)
        current_key = ''.join(key)
        entropy_value = calculate_entropy(current_key) if current_key else 0
        entropy_values.append(entropy_value)
        error_rates.append(error_rate_step)

        # Visualization step
        if update_step:
            eavesdropped = i in eavesdropped_bits
            update_step(alice_id, bob_id, i, alice_bits, alice_bases, bob_bases, measured_bit, eavesdropped=eavesdropped)

    qber = errors / length if length > 0 else 0
    return ''.join(key), qber, error_rates, entropy_values, eavesdropped_bits

# AES Encryption using QKD Key
def aes_encrypt(data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
    iv = cipher.iv
    if isinstance(data, str):
        data = data.encode('utf-8')
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(encrypted_data, key):
    raw_data = base64.b64decode(encrypted_data)
    iv = raw_data[:AES.block_size]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(raw_data[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')

# Key Padding
def pad_key(key, required_length=16):
    if not key:
        return None
    while len(key) < required_length:
        key += key[:required_length - len(key)]
    return key[:required_length]

# Calculate Entropy (Key Strength)
def calculate_entropy(key):
    counts = np.array([key.count('0'), key.count('1')])
    if np.any(counts == 0):
        return 0
    return entropy(counts, base=2)

# Smart Grid Node Class
class SmartGridNode:
    def __init__(self, node_id, name):
        self.node_id = node_id
        self.name = name
        self.keys = {}  # Keys shared with other nodes

# GUI Application
class QuantumCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Grid Simulation with Quantum Cryptography")
        self.root.geometry("800x700")

        # Initialize smart grid nodes
        self.nodes = [
            SmartGridNode(0, "Control Center"),
            SmartGridNode(1, "Substation 1"),
            SmartGridNode(2, "Substation 2"),
            SmartGridNode(3, "Smart Meter 1"),
            SmartGridNode(4, "Smart Meter 2"),
        ]

        # Variables for GUI elements
        self.selected_alice = tk.StringVar(value=self.nodes[0].name)
        self.selected_bob = tk.StringVar(value=self.nodes[1].name)
        self.key_length_var = tk.IntVar(value=32)
        self.error_rate_var = tk.DoubleVar(value=0.1)
        self.eavesdropping_var = tk.BooleanVar(value=False)

        self.setup_gui()

    def setup_gui(self):
        # Title Label
        ttk.Label(self.root, text="Smart Grid Simulation with Quantum Cryptography", font=("Arial", 16)).pack(pady=10)

        # Node Selection Frame
        node_frame = ttk.Frame(self.root)
        node_frame.pack(pady=10)

        ttk.Label(node_frame, text="Select Alice (Sender):").grid(row=0, column=0, padx=5, pady=5)
        ttk.Label(node_frame, text="Select Bob (Receiver):").grid(row=0, column=1, padx=5, pady=5)

        alice_menu = ttk.OptionMenu(node_frame, self.selected_alice, self.selected_alice.get(), *[node.name for node in self.nodes])
        bob_menu = ttk.OptionMenu(node_frame, self.selected_bob, self.selected_bob.get(), *[node.name for node in self.nodes])

        alice_menu.grid(row=1, column=0, padx=5, pady=5)
        bob_menu.grid(row=1, column=1, padx=5, pady=5)

        # Key Length and Error Rate
        param_frame = ttk.Frame(self.root)
        param_frame.pack(pady=10)

        ttk.Label(param_frame, text="Key Length (bits):").grid(row=0, column=0, padx=5, pady=5)
        self.key_length_spinbox = ttk.Spinbox(param_frame, from_=8, to=128, increment=8, textvariable=self.key_length_var)
        self.key_length_spinbox.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(param_frame, text="Error Rate:").grid(row=1, column=0, padx=5, pady=5)
        self.error_rate_spinbox = ttk.Spinbox(param_frame, from_=0, to=0.5, increment=0.01, textvariable=self.error_rate_var)
        self.error_rate_spinbox.grid(row=1, column=1, padx=5, pady=5)

        # Eavesdropping Option
        ttk.Checkbutton(self.root, text="Simulate Eavesdropping", variable=self.eavesdropping_var).pack(pady=5)

        # Data Entry
        ttk.Label(self.root, text="Enter Message to Send:").pack(pady=5)
        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.insert(0, "Energy Consumption Data")
        self.message_entry.pack(pady=5)

        # Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="Run BB84 Protocol Between Nodes", command=self.run_bb84_between_nodes).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(button_frame, text="Send Encrypted Message", command=self.send_encrypted_message).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(button_frame, text="Show Network Visualization", command=self.show_network_visualization).grid(row=0, column=2, padx=5, pady=5)

        # Output Text
        ttk.Label(self.root, text="Output:").pack(pady=5)
        self.output_text = tk.Text(self.root, height=15, wrap=tk.WORD)
        self.output_text.pack(pady=5)

    def update_visualization(self, alice_id, bob_id, step, alice_bits, alice_bases, bob_bases, measured_bit, eavesdropped=False):
        message = f"Step {step+1} between {self.nodes[alice_id].name} and {self.nodes[bob_id].name}:\n"
        message += f"Alice Bit: {alice_bits[step]}, Alice Basis: {alice_bases[step]}\n"
        message += f"Bob Basis: {bob_bases[step]}, Measured Bit: {measured_bit}\n"
        if eavesdropped:
            message += "Note: Eavesdropper altered this bit.\n"
        message += "\n"
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.root.update()

    def run_bb84_between_nodes(self):
        alice_name = self.selected_alice.get()
        bob_name = self.selected_bob.get()
        alice_id = [node.node_id for node in self.nodes if node.name == alice_name][0]
        bob_id = [node.node_id for node in self.nodes if node.name == bob_name][0]

        key_length = self.key_length_var.get()
        error_rate = self.error_rate_var.get()
        eavesdropping = self.eavesdropping_var.get()

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Running BB84 Protocol between {alice_name} and {bob_name}...\n")

        max_attempts = 5
        attempt = 0
        key_generated = False

        while attempt < max_attempts and not key_generated:
            key, qber, error_rates, entropy_values, eavesdropped_bits = bb84_protocol_visualized(
                alice_id, bob_id, length=key_length, error_rate=error_rate,
                eavesdropping=eavesdropping, update_step=self.update_visualization
            )

            if len(key) == 0:
                self.output_text.insert(tk.END, f"Attempt {attempt + 1}: No key bits generated. Retrying...\n")
                attempt += 1
            elif qber > error_rate:
                self.output_text.insert(tk.END, f"QBER too high ({qber:.2f}), key rejected!\n")
                if eavesdropping:
                    self.output_text.insert(tk.END, "Eavesdropping detected! The following bits were altered due to eavesdropping:\n")
                    self.output_text.insert(tk.END, f"{eavesdropped_bits}\n")
                attempt += 1
            else:
                key_generated = True
                padded_key = pad_key(key)
                key_entropy = calculate_entropy(key)
                self.output_text.insert(tk.END, f"Generated Key: {padded_key}\n")
                self.output_text.insert(tk.END, f"QBER: {qber:.2f}\n")
                self.output_text.insert(tk.END, f"Key Entropy (Strength): {key_entropy:.4f} bits\n")

                # Store the key in both nodes
                self.nodes[alice_id].keys[bob_id] = padded_key
                self.nodes[bob_id].keys[alice_id] = padded_key

                # Update network visualization
                self.show_network_visualization()

                # Show error rate and entropy graphs
                self.show_graph_window(error_rates, entropy_values)
                break

        if not key_generated:
            self.output_text.insert(tk.END, "Failed to generate a valid key after multiple attempts.\n")

    def send_encrypted_message(self):
        alice_name = self.selected_alice.get()
        bob_name = self.selected_bob.get()
        alice_id = [node.node_id for node in self.nodes if node.name == alice_name][0]
        bob_id = [node.node_id for node in self.nodes if node.name == bob_name][0]

        if bob_id not in self.nodes[alice_id].keys:
            messagebox.showerror("Error", f"No shared key between {alice_name} and {bob_name}. Run BB84 Protocol first.")
            return

        message = self.message_entry.get()
        aes_key = self.nodes[alice_id].keys[bob_id]

        try:
            # Alice encrypts the message
            encrypted_message = aes_encrypt(message, aes_key)
            self.output_text.insert(tk.END, f"{alice_name} sends encrypted message to {bob_name}: {encrypted_message}\n")

            # Bob decrypts the message
            decrypted_message = aes_decrypt(encrypted_message, aes_key)
            self.output_text.insert(tk.END, f"{bob_name} received and decrypted message: {decrypted_message}\n")
            self.output_text.insert(tk.END, "Secure communication completed.\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Decryption failed: {str(e)}\n")

    def show_graph_window(self, error_rates, entropy_values):
        # Create a new window for the graph
        graph_window = tk.Toplevel(self.root)
        graph_window.title("BB84 Protocol Visualization")
        graph_window.geometry("800x600")

        # Create Matplotlib Figure for Graphs
        fig = plt.Figure(figsize=(8, 6))
        ax1 = fig.add_subplot(211)
        ax2 = fig.add_subplot(212)

        ax1.set_title("Error Rate vs. Steps")
        ax1.set_xlabel("Steps")
        ax1.set_ylabel("Error Rate")
        ax2.set_title("Key Entropy vs. Steps")
        ax2.set_xlabel("Steps")
        ax2.set_ylabel("Key Entropy (bits)")

        # Plot the data
        ax1.plot(range(len(error_rates)), error_rates, label='Error Rate')
        ax2.plot(range(len(entropy_values)), entropy_values, label='Key Entropy')

        ax1.legend()
        ax2.legend()

        # Adjust layout
        fig.tight_layout()

        # Embed the plot in the new window
        canvas = FigureCanvasTkAgg(fig, master=graph_window)
        canvas.get_tk_widget().pack(pady=10)
        canvas.draw()

    def show_network_visualization(self):
        # Create a new window for the network visualization
        network_window = tk.Toplevel(self.root)
        network_window.title("Smart Grid Network Visualization")
        network_window.geometry("800x600")

        # Create a figure for the network graph
        fig, ax = plt.subplots(figsize=(8, 6))

        G = nx.Graph()
        labels = {}

        for node in self.nodes:
            G.add_node(node.node_id)
            labels[node.node_id] = node.name

        # Add edges for existing keys
        for node in self.nodes:
            for connected_node_id in node.keys:
                if node.node_id < connected_node_id:  # Avoid duplicate edges
                    G.add_edge(node.node_id, connected_node_id)

        # Set node colors based on node type
        node_colors = []
        for node in self.nodes:
            if "Control Center" in node.name:
                node_colors.append("red")
            elif "Substation" in node.name:
                node_colors.append("orange")
            elif "Smart Meter" in node.name:
                node_colors.append("lightblue")
            else:
                node_colors.append("gray")

        # Use a layout algorithm to position nodes
        pos = nx.spring_layout(G, seed=42)

        # Draw the network
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, ax=ax, node_size=500)
        nx.draw_networkx_edges(G, pos, ax=ax)
        nx.draw_networkx_labels(G, pos, labels, ax=ax, font_size=10)

        ax.set_title("Smart Grid Network")
        ax.axis('off')

        # Embed the plot in the new window
        canvas = FigureCanvasTkAgg(fig, master=network_window)
        canvas.get_tk_widget().pack()
        canvas.draw()

# Run the Application
if __name__ == "__main__":
    root = tk.Tk()
    app = QuantumCryptoApp(root)
    root.mainloop()

final working code
