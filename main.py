import random
import string


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

    if not characters:
        return "Error: No character types selected."

    password = []

    # Add at least one character from each selected type
    for char_set in required_chars:
        password.append(random.choice(char_set))

    # Fill the rest of the password
    password += random.choices(characters, k=pass_length - len(password))

    # Shuffle the password to ensure randomness
    random.shuffle(password)

    return "".join(password)


while True:
    try:
        user_input = input(
            "\nEnter the length of the password (or type 'exit' to quit): "
        )
        exit_commands = {"exit", "quit", "q", "e"}
        if isinstance(user_input, str) and user_input.strip().lower() in exit_commands:
            print("Exiting the password generator. Goodbye!")
            break

        try:
            pass_length = int(user_input)
        except ValueError:
            raise ValueError("Password length must be a valid number.")

        if pass_length <= 0:
            raise ValueError("Password length must be greater than 0.")

        has_letters = (
            input("Should the password contain letters? (y/n): ").lower() == "y"
        )
        has_numbers = (
            input("Should the password contain numbers? (y/n): ").lower() == "y"
        )
        has_special = (
            input("Should the password contain special characters? (y/n): ").lower()
            == "y"
        )

        password = generate_password(pass_length, has_letters, has_numbers, has_special)
        print(f"\nGenerated password with {len(password)} characters:\n" + password)

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    # Option to exit
    exit_choice = input("\nDo you want to generate another password? (y/n): ").lower()
    if exit_choice != "y":
        print("Exiting the password generator. Goodbye!")
        break
