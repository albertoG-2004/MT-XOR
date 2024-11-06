import re
import tkinter as tk
from tkinter import messagebox, scrolledtext
from Binary import get_binary
from Letter import get_word
from TuringMachine import TuringMachine

class TmInterfaz:
    def __init__(self, root):
        self.root = root
        self.root.title("Máquina de Turing - Cifrado XOR")
        self.root.geometry("600x600")
        self.root.configure(bg="#34495e")

        self.title_label = tk.Label(
            root, text="Máquina de Turing - Cifrado XOR", font=("Helvetica", 20, "bold"), bg="#34495e", fg="#ecf0f1"
        )
        self.title_label.pack(pady=20)

        self.label_sentence = tk.Label(
            root, text="Ingresa la oración:", font=("Helvetica", 14), bg="#34495e", fg="#bdc3c7"
        )
        self.label_sentence.pack(pady=10)

        self.entry_sentence = tk.Entry(root, font=("Helvetica", 14), width=50)
        self.entry_sentence.pack(pady=10)

        self.label_key = tk.Label(
            root, text="Ingresa un código de 8 dígitos binarios:", font=("Helvetica", 14), bg="#34495e", fg="#bdc3c7"
        )
        self.label_key.pack(pady=10)

        self.entry_key = tk.Entry(root, font=("Helvetica", 14), width=20)
        self.entry_key.pack(pady=10)

        self.encrypt_button = tk.Button(
            root, text="Cifrar", font=("Helvetica", 14, "bold"), bg="#1abc9c", fg="white", relief="flat", padx=10, pady=5, command=self.encrypt_message
        )
        self.encrypt_button.pack(pady=20)

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Helvetica", 14), width=50, height=10, bg="#34495e", fg="#ecf0f1")
        self.text_area.pack(pady=10)

        self.decrypt_button = tk.Button(
            root, text="Descifrar", font=("Helvetica", 14, "bold"), bg="#e74c3c", fg="white", relief="flat", padx=10, pady=5, command=self.decrypt_message
        )
        self.decrypt_button.pack(pady=10)

    def validate_sentence(self, sentence):
        return bool(re.match("^[A-ZÑ0-9 ]+$", sentence))

    def validate_xor_key(self, xor_key):
        return len(xor_key) == 8 and all(c in "01" for c in xor_key)

    def chunk_string(self, string, chunk_size):
        return [string[i:i + chunk_size] for i in range(0, len(string), chunk_size)]

    def encrypt_message(self):
        sentence = self.entry_sentence.get().upper()
        xor_key = self.entry_key.get()

        if not self.validate_sentence(sentence):
            self.show_error_popup("Entrada inválida. Solo se permiten letras sin acentos ni caracteres especiales, espacios y números.")
            return
        
        if not self.validate_xor_key(xor_key):
            self.show_error_popup("Código inválido. Solo se permiten 8 dígitos binarios (0s y 1s).")
            return

        words = sentence.split()
        encrypted_words = []
        tm = TuringMachine()

        for word in words:
            binary_word = get_binary(word)
            encrypted_word = [tm.xor_binary(b, xor_key) for b in binary_word]
            encrypted_words.append("".join(encrypted_word))

        encrypted_message = " ".join(encrypted_words)
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, f"Mensaje cifrado: {encrypted_message}")

    def decrypt_message(self):
        encrypted_message = self.text_area.get(1.0, tk.END).strip().replace("Mensaje cifrado: ", "")
        xor_key = self.entry_key.get()

        if not encrypted_message:
            self.show_error_popup("No hay mensaje cifrado para descifrar.")
            return
        
        decrypted_words = []
        tm = TuringMachine()

        for encrypted_word in encrypted_message.split():
            chunks = self.chunk_string(encrypted_word, 8)
            decrypted_binary = [tm.decrypt_xor_binary(b, xor_key) for b in chunks]
            decrypted_word = get_word(decrypted_binary)
            decrypted_words.append("".join(decrypted_word))

        decrypted_message = " ".join(decrypted_words)
        self.text_area.insert(tk.END, f"\nMensaje descifrado: {decrypted_message}")

    def show_error_popup(self, message):
        messagebox.showerror("Error", message)

if __name__ == "__main__":
    root = tk.Tk()
    app = TmInterfaz(root)
    root.mainloop()