import tkinter as tk
import tkinter.messagebox as msg
from tkinter import ttk
import random
import string
# import pyperclip

# Global variable to store the current password
current_password = ""
hidden_password = False


def generate_password(
    pass_length, uppercase=True, lowercase=True, numbers=True, special_chars=True
):
    char_sets = {
        "uppercase_letters": string.ascii_uppercase,
        "lowercase_letters": string.ascii_lowercase,
        "numbers": string.digits,
        "special_characters": string.punctuation,
    }

    characters = ""
    required_chars = []

    # Add selected character sets to the password pool and required list
    for key, char_set in char_sets.items():
        if (
            (key == "uppercase_letters" and uppercase)
            or (key == "lowercase_letters" and lowercase)
            or (key == "numbers" and numbers)
            or (key == "special_characters" and special_chars)
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
        if not user_input.isdigit():
            msg.showerror("Error", "Password length must be a valid number.")
            return

        pass_length = int(user_input)

        if pass_length <= 0:
            msg.showerror("Error", "Password length must be greater than 0.")
        elif pass_length > 128:
            msg.showerror("Error", "Password length must not exceed 128 characters.")
            return

        # has_letters = letters_var.get()
        has_uppercase = uppercase_var.get()
        has_lowercase = lowercase_var.get()
        has_numbers = numbers_var.get()
        has_special = special_var.get()

        # Check if at least one character type is selected
        if not (has_uppercase or has_lowercase or has_numbers or has_special):
            msg.showerror("Error", "No character types selected.")
            return

        current_password = generate_password(
            pass_length, has_uppercase, has_lowercase, has_numbers, has_special
        )

        if not current_password:
            return

        # Update the password input field
        label_password.delete(0, tk.END)
        label_password.insert(0, current_password)

        # Get password strength and assign colors
        strength, color, feedback = password_strength(current_password)

        # Update label contents
        label_strength.config(text=f"Password Quality: {strength}", foreground=color)
        label_feedback.config(text=feedback, foreground="black")

        if feedback:
            label_feedback.pack(side="left", pady=5, padx=10)
        else:
            label_feedback.pack_forget()

    except ValueError:
        msg.showerror("Error", "Password length must be a valid number.")
    except Exception as e:
        msg.showerror("Error", f"An unexpected error occurred: {e}")


def on_password_change(event=None):
    global current_password
    user_input_password = label_password.get()

    if user_input_password:
        current_password = user_input_password

        strength, color, feedback = password_strength(current_password)

        # Update strength label
        label_strength.config(text=f"Password Quality: {strength}", foreground=color)

        # Update feedback label
        label_feedback.config(text=feedback, foreground="black")
        if feedback:
            label_feedback.pack(side="left", pady=5, padx=5)
        else:
            label_feedback.pack_forget()
    else:
        # Clear strength indicators if input is empty
        label_strength.config(text="Password Quality:", foreground="black")
        label_feedback.pack_forget()


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
        level = "Poor"
        color = "red"
    elif strength <= 4:
        level = "Weak"
        color = "orange"
    elif strength <= 5:
        level = "Moderate"
        color = "#23A928"
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
        if not current_password:
            label_strength.config(text="Password Quality:")
        else:
            label_strength.config(text=f"Password Quality: {strength}")

        label_password.delete(0, tk.END)
        label_password.insert(0, current_password)
        label_feedback.config(text=feedback)
        button_hide.config(text="Hide")
        hidden_password = False
    else:
        label_password.delete(0, tk.END)
        label_password.insert(0, "*" * len(current_password))
        button_hide.config(text="Show")
        hidden_password = True


def clear_fields():
    global current_password, hidden_password
    # Clear the password length input field
    entry_length.delete(0, tk.END)

    # Reset the checkboxes to their default values (all checked)
    letters_var.set(True)
    uppercase_var.set(True)
    lowercase_var.set(True)
    numbers_var.set(True)
    special_var.set(True)

    current_password = ""  # Clear the stored password
    hidden_password = False

    # Clear the password display
    label_password.delete(0, tk.END)
    label_strength.config(text="Password Quality:", foreground="black")
    label_feedback.pack_forget()

    label_password.focus()


def copy_password():
    # Get the current generated password from the label
    # password = label_password.cget("text").replace("Generated password: ", "")

    # if password:  # Ensure there is a valid password to copy
    #     pyperclip.copy(password)  # Copy password to clipboard
    #     msg.showinfo("Success", "Password copied to clipboard!")
    pass


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
style.configure("TCheckbutton", background="#f0f4f8", font=("Arial", 10), borderwidth=0)

# password frame
password_frame = ttk.Frame(window)
password_frame.pack(anchor="w", pady=10, padx=10)

# Frame to hold password label and buttons
pass_display_frame = ttk.Frame(password_frame)
pass_display_frame.pack(padx=5)

label_password = ttk.Entry(pass_display_frame, font=("Arial", 12, "bold"), width=40)
label_password.pack(side="left", pady=5)
# Bind the <KeyRelease> event to trigger display_password when the user types
label_password.bind("<KeyRelease>", on_password_change)

# Frame for buttons
control_panel = ttk.Frame(pass_display_frame)
control_panel.pack(side="left", pady=5)

# password visibility button
button_hide = tk.Button(
    control_panel, text="Hide", command=password_visibility, borderwidth=0
)
button_hide.pack(side="left", padx=5)

# copy button
button_copy = tk.Button(
    control_panel, text="Copy Password", command=copy_password, borderwidth=0
)
button_copy.pack(side="left", padx=5)

label_strength = ttk.Label(password_frame, text="", font=("Arial", 12))
label_strength.configure(text="Password Quality:")
label_strength.pack(side="left", padx=5)

# Frame for Checkboxes
checkbox_frame = ttk.Frame(window, width=300)
checkbox_frame.configure(borderwidth=3, relief="groove")
checkbox_frame.pack(anchor="w", pady=10, padx=10)

# Frame for length input (First Line)
length_frame = ttk.Frame(checkbox_frame)
length_frame.pack(fill="x", padx=5, pady=2)

# Label and Entry for password length
label_length = ttk.Label(length_frame, text="Length:")
label_length.pack(side="left", padx=5)

entry_length = ttk.Entry(length_frame, width=5)
entry_length.pack(side="left", padx=5)

# Frame for checkboxes (Second Line)
checkbox_container = ttk.Frame(checkbox_frame)
checkbox_container.pack(fill="x", padx=5, pady=2)

characters_label = ttk.Label(checkbox_container, text="Character Types")
characters_label.pack(anchor="w", pady=10, padx=5)

# Define BooleanVars
letters_var = tk.BooleanVar(value=True)
uppercase_var = tk.BooleanVar(value=True)
lowercase_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
special_var = tk.BooleanVar(value=True)

# Checkboxes to select character types
uppercase_check = ttk.Checkbutton(
    checkbox_container, text="A-Z", variable=uppercase_var, width=10
)
uppercase_check.pack(side="left", padx=5)

lowercase_check = ttk.Checkbutton(
    checkbox_container, text="a-z", variable=lowercase_var, width=10
)
lowercase_check.pack(side="left", padx=5)

numbers_check = ttk.Checkbutton(
    checkbox_container, text="0-9", variable=numbers_var, width=10
)
numbers_check.pack(side="left", padx=5)

special_check = ttk.Checkbutton(
    checkbox_container, text="/*+&...", variable=special_var, width=10
)
special_check.pack(side="left", padx=5)

# show password feedback label
label_feedback = ttk.Label(checkbox_frame, text="", font=("Arial", 10))

# Frame for the password handler buttons
pass_action_buttons = ttk.Frame(window)
pass_action_buttons.pack(pady=5, padx=10, anchor="e")

# celar button
button_clear = tk.Button(
    pass_action_buttons, text="Clear", command=clear_fields, borderwidth=0
)
button_clear.pack(side="left", padx=10)

# generate button
button_generate = ttk.Button(
    pass_action_buttons, text="Generate Password", command=display_password
)
button_generate.pack(side="left", pady=10)

window.mainloop()
