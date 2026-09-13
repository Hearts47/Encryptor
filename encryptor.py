import os
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path

SALT_SIZE = 16  # 16 bytes de salt préfixés dans chaque fichier .enc


class DirectoryEncryptor:
    def __init__(self, password=None):
        self.password = password or getpass.getpass("Entrez le mot de passe : ")

    def _derive_key(self, salt):
        """Dériver une clé à partir du mot de passe et d'un salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password.encode()))

    def encrypt_file(self, file_path):
        """Chiffrer un fichier — le salt est préfixé dans le .enc"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Générer un salt unique pour ce fichier
            salt = os.urandom(SALT_SIZE)
            key = self._derive_key(salt)
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(file_data)

            # Structure du fichier : [16 bytes salt][données chiffrées]
            encrypted_file_path = str(file_path) + '.enc'
            with open(encrypted_file_path, 'wb') as f:
                f.write(salt + encrypted_data)

            os.remove(file_path)
            print(f"✓ Fichier chiffré : {file_path}")
            return True

        except Exception as e:
            print(f"✗ Erreur lors du chiffrement de {file_path}: {str(e)}")
            return False

    def decrypt_file(self, file_path):
        """Déchiffrer un fichier — le salt est lu depuis les premiers bytes"""
        try:
            with open(file_path, 'rb') as f:
                raw = f.read()

            # Extraire le salt (16 premiers bytes) et les données chiffrées
            salt = raw[:SALT_SIZE]
            encrypted_data = raw[SALT_SIZE:]

            key = self._derive_key(salt)
            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_data)

            decrypted_file_path = str(file_path)[:-4]  # Supprime '.enc'
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)

            os.remove(file_path)
            print(f"✓ Fichier déchiffré : {file_path}")
            return True

        except Exception as e:
            print(f"✗ Erreur lors du déchiffrement de {file_path}: {str(e)}")
            return False

    def encrypt_directory(self, directory_path, recursive=True):
        """Chiffrer tous les fichiers dans un répertoire"""
        directory = Path(directory_path)

        if not directory.exists():
            print(f"Erreur : Le répertoire {directory_path} n'existe pas")
            return

        print(f"Chiffrement du répertoire : {directory_path}")
        print("-" * 50)

        file_count = 0
        success_count = 0

        files = directory.rglob('*') if recursive else directory.iterdir()
        for file_path in files:
            if file_path.is_file() and not file_path.name.endswith('.enc'):
                file_count += 1
                if self.encrypt_file(file_path):
                    success_count += 1

        print("-" * 50)
        print(f"Résultat : {success_count}/{file_count} fichiers chiffrés")

    def decrypt_directory(self, directory_path, recursive=True):
        """Déchiffrer tous les fichiers dans un répertoire"""
        directory = Path(directory_path)

        if not directory.exists():
            print(f"Erreur : Le répertoire {directory_path} n'existe pas")
            return

        print(f"Déchiffrement du répertoire : {directory_path}")
        print("-" * 50)

        file_count = 0
        success_count = 0

        files = directory.rglob('*') if recursive else directory.iterdir()
        for file_path in files:
            if file_path.is_file() and file_path.name.endswith('.enc'):
                file_count += 1
                if self.decrypt_file(file_path):
                    success_count += 1

        print("-" * 50)
        print(f"Résultat : {success_count}/{file_count} fichiers déchiffrés")


def main():
    print("=== Logiciel de chiffrement de répertoire ===")
    print()

    password = getpass.getpass("Entrez le mot de passe : ")
    encryptor = DirectoryEncryptor(password)

    while True:
        print("\nOptions :")
        print("1. Chiffrer un répertoire")
        print("2. Déchiffrer un répertoire")
        print("3. Quitter")

        choice = input("\nChoisissez une option (1-3) : ").strip()

        if choice == '1':
            directory = input("Entrez le chemin du répertoire à chiffrer : ").strip()
            recursive = input("Chiffrer récursivement ? (y/n) : ").strip().lower() == 'y'
            encryptor.encrypt_directory(directory, recursive)

        elif choice == '2':
            directory = input("Entrez le chemin du répertoire à déchiffrer : ").strip()
            recursive = input("Déchiffrer récursivement ? (y/n) : ").strip().lower() == 'y'
            encryptor.decrypt_directory(directory, recursive)

        elif choice == '3':
            print("Au revoir !")
            break

        else:
            print("Option invalide. Veuillez réessayer.")


if __name__ == "__main__":
    try:
        import cryptography
    except ImportError:
        print("Veuillez installer les dépendances avec : pip install cryptography")
        exit(1)

    main()
