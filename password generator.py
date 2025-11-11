import tkinter as tk
from tkinter import ttk
import string
import secrets
import pyperclip

# --- 1. Password Generation Logic ---

def generate_secure_password(length, use_upper, use_lower, use_digits, use_symbols):
    """Generates a cryptographically strong random password."""

    character_sets = []
    if use_lower:
        character_sets.append(string.ascii_lowercase)
    if use_upper:
        character_sets.append(string.ascii_uppercase)
    if use_digits:
        character_sets.append(string.digits)
    if use_symbols:
        character_sets.append('!@#$%^&*()-_=+[]{}|;:,.<>?')

    if not character_sets:
        return "Error: Select at least one character type."

    all_characters = "".join(character_sets)
    password = []

    # Ensure at least one character from each chosen type
    for char_set in character_sets:
        password.append(secrets.choice(char_set))

    remaining_length = max(length - len(password), 0)
    password.extend(secrets.choice(all_characters) for _ in range(remaining_length))

    # Shuffle for randomness
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


# --- 2. GUI Application Setup ---

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure Password Generator")
        master.geometry("1000x400")
        master.resizable(False, False)

        # --- Dark Theme ---
        style = ttk.Style()
        style.theme_use('clam')

        COLOR_BG_DARK = "#283747"
        COLOR_FRAME_LIGHT = "#34495e"
        COLOR_ACCENT = "#1abc9c"
        COLOR_TEXT = "#ecf0f1"

        master.configure(bg=COLOR_BG_DARK)

        # Widget Styles
        style.configure("TLabel", background=COLOR_FRAME_LIGHT, foreground=COLOR_TEXT, font=('Inter', 10))
        style.configure("Title.TLabel", font=('Inter', 16, 'bold'), foreground=COLOR_ACCENT, background=COLOR_BG_DARK)
        style.configure("Card.TFrame", background=COLOR_FRAME_LIGHT, borderwidth=2, relief="groove")
        style.configure("TCheckbutton", background=COLOR_FRAME_LIGHT, foreground=COLOR_TEXT)
        style.configure("TScale", background=COLOR_FRAME_LIGHT)
        style.configure("Generate.TButton",
                        font=('Inter', 12, 'bold'),
                        background=COLOR_ACCENT,
                        foreground=COLOR_BG_DARK,
                        padding=10)
        style.map("Generate.TButton", background=[('active', '#16a085')])

        # Variables
        self.password_length = tk.IntVar(value=16)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.status_text = tk.StringVar(value="Configure and press Generate")

        # Main Frame
        main_frame = ttk.Frame(master, padding="25", style="Card.TFrame")
        main_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Label(master, text="Password Strength Builder", style="Title.TLabel").pack(pady=(15, 5))

        # Length Frame
        length_frame = ttk.Frame(main_frame, style="TFrame")
        length_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(10, 15))

        ttk.Label(length_frame, text="Length:", font=('Inter', 10, 'bold')).pack(side='left', padx=(0, 5))
        ttk.Label(length_frame, textvariable=self.password_length, width=3, font=('Inter', 10, 'bold'),
                  foreground=COLOR_ACCENT).pack(side='left', padx=(0, 10))

        self.length_scale = ttk.Scale(
            length_frame,
            from_=8,
            to=32,
            orient=tk.HORIZONTAL,
            variable=self.password_length,
            command=self.update_length_label,
            length=300
        )
        self.length_scale.pack(fill='x', expand=True)

        # Checkboxes
        style.configure("Checkbox.TCheckbutton", padding=5, background=COLOR_FRAME_LIGHT, foreground=COLOR_TEXT)
        ttk.Checkbutton(main_frame, text="Uppercase (A-Z)", variable=self.use_upper, style="Checkbox.TCheckbutton").grid(row=1, column=0, sticky='w', padx=10, pady=5)
        ttk.Checkbutton(main_frame, text="Lowercase (a-z)", variable=self.use_lower, style="Checkbox.TCheckbutton").grid(row=1, column=1, sticky='w', padx=10, pady=5)
        ttk.Checkbutton(main_frame, text="Numbers (0-9)", variable=self.use_digits, style="Checkbox.TCheckbutton").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        ttk.Checkbutton(main_frame, text="Symbols (!@#...)", variable=self.use_symbols, style="Checkbox.TCheckbutton").grid(row=2, column=1, sticky='w', padx=10, pady=5)

        # Generate Button
        self.generate_button = ttk.Button(
            main_frame,
            text="GENERATE & COPY PASSWORD",
            command=self.generate_and_display,
            style="Generate.TButton"
        )
        self.generate_button.grid(row=3, column=0, columnspan=2, sticky='ew', padx=5, pady=(20, 10))

        # Password Display
        self.password_display = tk.Entry(
            main_frame,
            width=50,
            font=('Courier', 14, 'bold'),
            justify='center',
            fg=COLOR_ACCENT,
            bg="#1e2b38",
            relief=tk.FLAT,
            bd=3,
            highlightthickness=1,
            highlightbackground="#4a657c",
            highlightcolor=COLOR_ACCENT,
            insertbackground=COLOR_ACCENT
        )
        self.password_display.grid(row=4, column=0, columnspan=2, sticky='ew', padx=5, pady=5)
        self.password_display.insert(0, "Click Generate")

        # Status Label
        self.status_label = ttk.Label(main_frame, textvariable=self.status_text, anchor="center")
        self.status_label.grid(row=5, column=0, columnspan=2, sticky='ew', pady=5)

    def update_length_label(self, value):
        self.password_length.set(int(float(value)))

    def generate_and_display(self):
        length = self.password_length.get()
        use_upper = self.use_upper.get()
        use_lower = self.use_lower.get()
        use_digits = self.use_digits.get()
        use_symbols = self.use_symbols.get()

        self.status_text.set("Generating...")

        new_password = generate_secure_password(length, use_upper, use_lower, use_digits, use_symbols)

        if new_password.startswith("Error"):
            self.show_custom_message("Configuration Error", new_password, "red")
            self.status_text.set("Error: Select character types.")
            return

        self.password_display.delete(0, tk.END)
        self.password_display.insert(0, new_password)

        try:
            pyperclip.copy(new_password)
            self.status_text.set("Password copied to clipboard.")
        except Exception:
            self.show_custom_message("Clipboard Warning",
                                     "Could not copy to clipboard.\nInstall pyperclip or copy manually.",
                                     "orange")
            self.status_text.set(" Copy failed.")

    def show_custom_message(self, title, message, color):
        top = tk.Toplevel(self.master)
        top.title(title)
        top.geometry("320x120")
        top.configure(bg="#283747")
        top.resizable(False, False)
        tk.Label(top, text=message, bg="#283747", fg=color,
                 font=('Inter', 10, 'bold'), wraplength=280).pack(padx=15, pady=15)
        ttk.Button(top, text="OK", command=top.destroy).pack(pady=5)


# --- 3. Run the App ---
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
