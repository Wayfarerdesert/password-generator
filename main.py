import tkinter as tk
import tkinter.messagebox as msg
from tkinter import ttk
import random
import string
import pyperclip

# Global variable to store the current password
current_password = ""
hidden_password = False


def generate_password(pass_length, letters=True, numbers=True, special_chars=True):
    char_sets = {
        "letters": string.ascii_letters,
        "numbers": string.digits,
        "special": string.punctuation,
    }

    characters = ""
    required_chars = []

    # Add selected character sets to the password pool and required list
    for key, char_set in char_sets.items():
        if (
            (key == "letters" and letters)
            or (key == "numbers" and numbers)
            or (key == "special" and special_chars)
        ):
            characters += char_set
            required_chars.append(char_set)

    password = []

    # Add at least one character from each selected type
    for char_set in required_chars:
        password.append(random.choice(char_set))

    # Fill the rest of the password
    password += random.choices(characters, k=pass_length - len(password))

    # Shuffle the password to ensure randomness
    random.shuffle(password)

    return "".join(password)


def display_password():
    global current_password, hidden_password

    try:
        user_input = entry_length.get().strip()

        # Validate input
        if not user_input:
            msg.showerror("Error", "Please enter a password length.")
            return
        if not user_input.isdigit():
            msg.showerror("Error", "Password length must be a valid number.")
            return

        pass_length = int(user_input)

        if pass_length <= 0:
            msg.showerror("Error", "Password length must be greater than 0.")
            return

        has_letters = letters_var.get()
        has_numbers = numbers_var.get()
        has_special = special_var.get()

        # Check if at least one character type is selected
        if not (has_letters or has_numbers or has_special):
            msg.showerror("Error", "No character types selected.")
            return

        current_password = generate_password(
            pass_length, has_letters, has_numbers, has_special
        )

        if not current_password:
            return

        # Get password strength and assign colors
        strength, color, feedback = password_strength(current_password)

        # Update label contents
        label_strength.config(text=f"{strength}\n", foreground=color)
        label_feedback.config(text=feedback, foreground="black")
        label_password.config(text=current_password)

        # Display elements in a single line
        password_frame.pack()
        password_wrapper.pack()
        label_strength.pack()

        if feedback:
            label_feedback.pack()
        else:
            label_feedback.pack_forget()

        label_password.pack(padx=5)

        # Display the buttons
        control_panel.pack(pady=5)
        button_hide.config(text="Hide")
        button_hide.pack(side="left", padx=5)

        button_copy.pack(side="left", padx=5)
        button_clear.pack(side="left", padx=5)

    except ValueError:
        msg.showerror("Error", "Password length must be a valid number.")
    except Exception as e:
        msg.showerror("Error", f"An unexpected error occurred: {e}")


def password_strength(password):
    # Define the character sets
    char_sets = {
        "letters": string.ascii_letters,
        "numbers": string.digits,
        "special characters": string.punctuation,
    }

    strength = 0
    feedback = []

    # Check for each character set
    for key, char_set in char_sets.items():
        if any(char in char_set for char in password):
            strength += 1
        else:
            feedback.append(f"\nAdd {key.lower()} for a stronger password.")

    # Length-based scoring (max +3 points)
    length = len(password)
    if length >= 16:
        strength += 3
    elif length >= 12:
        strength += 2
    elif length >= 8:
        strength += 1
    else:
        feedback.append("\nUse at least 8 characters for better security.")

    # Strength Level Assessment
    if strength <= 3:
        level = "Weak"
        color = "red"
    elif 4 <= strength <= 5:
        level = "Moderate"
        color = "orange"
    else:
        level = "Strong"
        color = "green"

    # Ensure feedback is properly formatted
    feedback_text = "".join(feedback) if feedback else ""

    return level, color, feedback_text


def password_visibility():
    global hidden_password, current_password
    strength, color, feedback = password_strength(current_password)

    if hidden_password:
        label_strength.config(text=f"{strength}\n")
        label_feedback.config(text=feedback)
        label_password.config(text=current_password)
        button_hide.config(text="Hide")
        hidden_password = False
    else:
        label_password.config(text="*" * len(current_password))
        button_hide.config(text="Show")
        hidden_password = True


def clear_fields():
    global current_password, hidden_password
    # Clear the password length input field
    entry_length.delete(0, tk.END)

    # Reset the checkboxes to their default values (all checked)
    letters_var.set(True)
    numbers_var.set(True)
    special_var.set(True)

    current_password = ""  # Clear the stored password
    hidden_password = False

    # Clear the password display
    password_frame.pack_forget()
    control_panel.pack_forget()

    entry_length.focus()


def copy_password():
    # Get the current generated password from the label
    password = label_password.cget("text").replace("Generated password: ", "")

    if password:  # Ensure there is a valid password to copy
        pyperclip.copy(password)  # Copy password to clipboard
        msg.showinfo("Success", "Password copied to clipboard!")


# Tkinter GUI Setup
# Create the main window
window = tk.Tk()
window.title("Password Generator")
window.configure(bg="#f0f0f0")

# Style Configuration
style = ttk.Style()
style.theme_use("clam")

# Custom Styles
style.configure("TLabel", background="#f0f4f8", font=("Arial", 11))
style.configure(
    "TButton",
    background="#4CAF50",
    foreground="white",
    font=("Arial", 10),
    padding=6,
    borderwidth=0,
)
style.map("TButton", background=[("active", "#45a049")])  # Hover effect
style.configure(
    "TCheckbutton",
    background="#f0f4f8",
    font=("Arial", 10),
    borderwidth=0,
)

# Label for password length
label_length = ttk.Label(window, text="Enter the length of the password:")
label_length.pack(pady=2)

# Label for password length
entry_length = ttk.Entry(window)
entry_length.pack(pady=15)

# Frame for Checkboxes
checkbox_frame = ttk.Frame(window)
checkbox_frame.pack(pady=5)

# Checkboxes to select character types
letters_var = tk.BooleanVar(value=True)
letters_check = ttk.Checkbutton(checkbox_frame, text="Letters", variable=letters_var)
letters_check.pack(side="left", pady=2, padx=5)

numbers_var = tk.BooleanVar(value=True)
numbers_check = ttk.Checkbutton(checkbox_frame, text="Numbers", variable=numbers_var)
numbers_check.pack(side="left", pady=2, padx=5)

special_var = tk.BooleanVar(value=True)
special_check = ttk.Checkbutton(
    checkbox_frame, text="Special Characters", variable=special_var
)
special_check.pack(side="left", pady=2, padx=5)

# generate button
button_generate = ttk.Button(window, text="Generate Password", command=display_password)
button_generate.pack(pady=10)

# password frame
password_frame = ttk.Frame(window)

# label to display the generated password
password_wrapper = ttk.Label(
    password_frame, text="Generated Password: ", font=("Arial", 12)
)
label_strength = ttk.Label(password_frame, text="", font=("Arial", 12))
label_feedback = ttk.Label(password_frame, text="", font=("Arial", 10))
label_password = ttk.Label(password_frame, text="", font=("Arial", 12, "bold"))

# Frame for buttons
control_panel = ttk.Frame(window)

# password visibility button
button_hide = tk.Button(
    control_panel, text="Hide", command=password_visibility, borderwidth=0
)

# copy button
button_copy = tk.Button(
    control_panel, text="Copy Password", command=copy_password, borderwidth=0
)

# celar button
button_clear = tk.Button(
    control_panel, text="Clear", command=clear_fields, borderwidth=0
)

window.mainloop()
