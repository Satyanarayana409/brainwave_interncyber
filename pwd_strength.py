import random
import string
import re
from zxcvbn import zxcvbn
def password_strength_cracktime(password):
    result = zxcvbn(password)
    score = result['score']
    percentage = (score / 4) * 100
    print("Score of the password:", score)
    print("Percentage score:", percentage)
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    print("Time to crack the password:", crack_time)

def validation(password):
    if len(password) < 8:
        print("Password should be at least 8 characters long, preferably more than 12 characters.")
    if not re.search(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(){}[\]|\\_\-+=,.?/><:;"])', password):
        print("Password must contain at least one lowercase letter, one uppercase letter, one digit, and one specia>

def generate_password(character_count):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(character_count))
    while not (any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c >
        password = ''.join(random.choice(characters) for _ in range(character_count))
    print("Generated password:", password)
    password_strength_cracktime(password)

def main():
    print("Choose an option:")
    print("1. Generate a password and check its strength")
    print("2. Validate a password and check its strength")

    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        character_count = int(input("Enter the desired character count for the password: "))
        generate_password(character_count)
    elif choice == '2':
        password = input("Enter the password to validate: ")
        validation(password)
        password_strength_cracktime(password)
    else:
        print("Invalid choice. Please enter either 1 or 2.")

if __name__ == "__main__":
    main()
