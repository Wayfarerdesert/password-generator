import tkinter as tk
import tkinter.messagebox as msg
import random
import string
import pyperclip


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
    try:
        pass_length = int(entry_length.get())
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

        password = generate_password(pass_length, has_letters, has_numbers, has_special)

        if password is None:
            return

        # Display the generated password
        label_password.config(text=f"Generated Password:\n{password}")
        label_password.pack()

        # Display the clear and copy button
        button_copy.pack()
        button_clear.pack()

    except ValueError:
        msg.showerror("Error", "Password length must be a valid number.")
    except Exception as e:
        msg.showerror("Error", f"An unexpected error occurred: {e}")


def clear_button():
    # Clear the password length input field
    entry_length.delete(0, tk.END)

    # Reset the checkboxes to their default values (all checked)
    letters_var.set(True)
    numbers_var.set(True)
    special_var.set(True)

    label_password.config(text="")

    entry_length.focus()

    # Hide the Clear and Copy buttons after it's used
    button_copy.pack_forget()
    button_clear.pack_forget()


def copy_password():
    # Get the current generated password from the label
    password = label_password.cget("text").replace("Generated password: ", "")

    if password:  # Ensure there is a valid password to copy
        pyperclip.copy(password)  # Copy password to clipboard
        msg.showinfo("Success", "Password copied to clipboard!")


# Create the main window
window = tk.Tk()
window.title("Password Generator")

# Function to generate a password based on user input
label_length = tk.Label(window, text="Enter the length of the password:")
label_length.pack()

entry_length = tk.Entry(window)
entry_length.pack()

# Checkboxes to select character types
letters_var = tk.BooleanVar(value=True)
letters_check = tk.Checkbutton(window, text="Letters", variable=letters_var)
letters_check.pack()

numbers_var = tk.BooleanVar(value=True)
numbers_check = tk.Checkbutton(window, text="Numbers", variable=numbers_var)
numbers_check.pack()

special_var = tk.BooleanVar(value=True)
special_check = tk.Checkbutton(window, text="Special Characters", variable=special_var)
special_check.pack()

# generate button
button_generate = tk.Button(window, text="Generate Password", command=display_password)
button_generate.pack()

# copy button
button_copy = tk.Button(window, text="Copy Password", command=copy_password)

# celar button
button_clear = tk.Button(window, text="Clear", command=clear_button)

# label to display the generated password
label_password = tk.Label(window, text="")

window.mainloop()
