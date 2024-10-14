import csv
import os
import argparse
import getpass

from pckgs.crpt.sync_encryptor import SyncEncryptor

FILE_NAME_ACCESS_LIST = 'access_list.csv'


def get_next_item_number(csv_filename):
    if not os.path.exists(csv_filename):
        return 1
    with open(csv_filename, mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)
        if len(rows) > 1:
            last_item = int(rows[-1][0])
            return last_item + 1
        else:
            return 1


def add_access(passphrase, login, password, description=None):
    item_number = get_next_item_number(FILE_NAME_ACCESS_LIST)
    encryptor = SyncEncryptor(passphrase)
    encrypted_password, salt = encryptor.encrypt(password, use_salt=True)

    with open(FILE_NAME_ACCESS_LIST, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([item_number, login, encrypted_password, description if description else '', salt])


def show_access_entry(item_number, passphrase):
    with open(FILE_NAME_ACCESS_LIST, mode='r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            if row[0] == item_number:
                encryptor = SyncEncryptor(passphrase)
                print(f"Item: {row[0]}")
                print(f"Login: {row[1]}")
                print(f"Password: {encryptor.decrypt(row[2], row[4])}")
                print(f"Description: {row[3] if row[3] else 'No description'}")
                print(f"Salt: {row[4]}")
                break
        else:
            print(f"No entry found for item: {item_number}")


def display_access_list():
    with open(FILE_NAME_ACCESS_LIST, mode='r') as file:
        reader = csv.reader(file)
        next(reader)
        print(f"{'Item':<5}{'Login':<20}{'Description':<30}")
        print("-" * 60)
        for row in reader:
            item = row[0]
            login = row[1]
            description = row[3] if row[3] else "No description"
            print(f"{item:<5}{login:<20}{description:<30}")


def get_passphrase():
    passphrase = getpass.getpass("Enter passphrase: ").strip()
    confirm_passphrase = getpass.getpass("Confirm passphrase: ").strip()

    if not passphrase:
        print("Passphrase is required!")
        return None

    if passphrase != confirm_passphrase:
        print("Passphrases do not match! Script will now exit.")
        return None

    return passphrase


def main():
    parser = argparse.ArgumentParser(description='Add access to access_list.csv')
    parser.add_argument('--add-access', action='store_true', help='Add a new access entry')
    parser.add_argument('--access-list', action='store_true', help='Show list of logins and descriptions')
    parser.add_argument('--access', action='store_true', help='Show full access entry by item number')

    args = parser.parse_args()

    if args.add_access:
        login = input("Enter login: ").strip()
        if not login:
            print("Login is required!")
            return

        password = input("Enter secret: ").strip()
        if not password:
            print("Secret is required!")
            return

        description = input("Enter description (optional): ").strip()

        passphrase = get_passphrase()
        if passphrase:
            print("Passphrase set successfully.")
        else:
            print("Failed to set passphrase.")

        add_access(passphrase, login, password, description)
        print("Access added successfully.")

    if args.access_list:
        display_access_list()

    if args.access:
        item = input("Enter item: ").strip()
        if not item:
            print("Item is required!")
            return
        passphrase = getpass.getpass("Enter passphrase: ").strip()
        if not passphrase:
            print("Passphrase is required!")
            return

        show_access_entry(item, passphrase)


if __name__ == "__main__":
    main()