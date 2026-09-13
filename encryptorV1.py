import os
import hashlib
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path

class DirectoryEncryptor:
    def __init__(self, password=None):
        self.password = password or getpass.getpass("Entrez le mot de passe : ")
        self.salt = b'salt_1234567890'  # Vous pouvez améliorer cela avec un salt aléatoire
        self.key = self._derive_key()
        self.cipher = Fernet(self.key)

    def _derive_key(self):
        """Dériver une clé à partir du mot de passe"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
        return key

    def encrypt_file(self, file_path):
        """Chiffrer un fichier"""
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()

            encrypted_data = self.cipher.encrypt(file_data)

            # Sauvegarder le fichier chiffré avec l'extension .enc
            encrypted_file_path = str(file_path) + '.enc'
            with open(encrypted_file_path, 'wb') as file:
                file.write(encrypted_data)

            # Supprimer le fichier original
            os.remove(file_path)

            print(f"✓ Fichier chiffré : {file_path}")
            return True

        except Exception as e:
            print(f"✗ Erreur lors du chiffrement de {file_path}: {str(e)}")
            return False

    def decrypt_file(self, file_path):
        """Déchiffrer un fichier"""
        try:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()

            decrypted_data = self.cipher.decrypt(encrypted_data)

            # Sauvegarder le fichier déchiffré en supprimant l'extension .enc
            decrypted_file_path = str(file_path)[:-4]  # Supprime '.enc'
            with open(decrypted_file_path, 'wb') as file:
                file.write(decrypted_data)

            # Supprimer le fichier chiffré original
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

        # Compter les fichiers
        file_count = 0
        success_count = 0

        if recursive:
            # Parcourir récursivement tous les fichiers
            for file_path in directory.rglob('*'):
                if file_path.is_file() and not file_path.name.endswith('.enc'):
                    file_count += 1
                    if self.encrypt_file(file_path):
                        success_count += 1
        else:
            # Parcourir uniquement le répertoire principal
            for file_path in directory.iterdir():
                if file_path.is_file() and not file_path.name.endswith('.enc'):
                    file_count += 1
                    if self.encrypt_file(file_path):
                        success_count += 1

        print("-" * 50)
        print(f"Résultat : {success_count}/{file_count} fichiers traités")

    def decrypt_directory(self, directory_path, recursive=True):
        """Déchiffrer tous les fichiers dans un répertoire"""
        directory = Path(directory_path)

        if not directory.exists():
            print(f"Erreur : Le répertoire {directory_path} n'existe pas")
            return

        print(f"Déchiffrement du répertoire : {directory_path}")
        print("-" * 50)

        # Compter les fichiers
        file_count = 0
        success_count = 0

        if recursive:
            # Parcourir récursivement tous les fichiers
            for file_path in directory.rglob('*'):
                if file_path.is_file() and file_path.name.endswith('.enc'):
                    file_count += 1
                    if self.decrypt_file(file_path):
                        success_count += 1
        else:
            # Parcourir uniquement le répertoire principal
            for file_path in directory.iterdir():
                if file_path.is_file() and file_path.name.endswith('.enc'):
                    file_count += 1
                    if self.decrypt_file(file_path):
                        success_count += 1

        print("-" * 50)
        print(f"Résultat : {success_count}/{file_count} fichiers traités")

def main():
    print("=== Logiciel de chiffrement de répertoire ===")
    print()

    # Demander le mot de passe
    password = getpass.getpass("Entrez le mot de passe : ")

    # Créer l'encrypteur
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
    # Installer les dépendances si nécessaire
    try:
        import base64
        import cryptography
    except ImportError:
        print("Veuillez installer les dépendances avec : pip install cryptography")
        exit(1)

    main()
