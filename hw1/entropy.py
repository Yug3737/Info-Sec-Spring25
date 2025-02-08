# file: entropy.py
# author: Yug Patel
# last modified: 8 February 2025

import math


def is_special_character(char):
    char_ascii_value = ord(char)
    if (
        33 <= char_ascii_value <= 47
        or 58 <= char_ascii_value <= 64
        or 91 <= char_ascii_value <= 96
        or 123 <= char_ascii_value <= 126
    ):
        return True
    else:
        return False


def is_uppercase(char):
    char_ascii_value = ord(char)
    if 65 <= char_ascii_value <= 90:
        return True
    else:
        return False


def is_lowercase(char):
    char_ascii_value = ord(char)
    if 97 <= char_ascii_value <= 122:
        return True
    else:
        return False


def is_number(char):
    char_ascii_value = ord(char)
    if 48 <= char_ascii_value <= 57:
        return True
    else:
        return False


def compute_password_range(password):
    password_range = 0
    # we just need to detect the type of chararcters present in the password
    # ASCII value range:
    # lowercase letters: 97-122
    # uppercase letters: 65-90
    # special characters: 33-47, 58-64, 91-96, 123-126
    (
        password_has_number,
        password_has_lowercase,
        password_has_uppercase,
        password_has_special_char,
    ) = (False, False, False, False)

    for i in range(len(password)):
        if is_number(password[i]):
            password_has_number = True
        elif is_uppercase(password[i]):
            password_has_uppercase = True
        elif is_lowercase(password[i]):
            password_has_lowercase = True
        elif is_special_character(password[i]):
            password_has_special_char = True
        else:
            print(f"invalid char in password: {password[i]}")
            exit(0)

    if password_has_number:
        password_range += 10
    if password_has_lowercase:
        password_range += 26
    if password_has_uppercase:
        password_range += 26
    if password_has_special_char:
        password_range += 32
    return password_range


def compute_entropy(length, range):
    return length * math.log2(range)


def main():
    input_password = input("Enter your password:")
    input_password_len = len(input_password)
    input_password_range = compute_password_range(input_password)
    entropy = compute_entropy(input_password_len, input_password_range)
    # entropy = round(entropy, 2)
    print("Entropy of your password is:", entropy, "bits.")


if __name__ == "__main__":
    main()
