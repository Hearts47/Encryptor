import os
import base64
import getpass
import struct
import uuid
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
        """
        Chiffrer un fichier.
        Structure du fichier .enc :
          [16 bytes salt][4 bytes longueur nom][nom original chiffré][données chiffrées]
        Le fichier est renommé en <uuid>.enc pour masquer son identité.
        """
        file_path = Path(file_path)

        # Bloquer le re-chiffrement
        if file_path.suffix == '.enc':
            print(f"⚠ Ignoré (déjà chiffré) : {file_path}")
            return False

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Générer un salt unique pour ce fichier
            salt = os.urandom(SALT_SIZE)
            key = self._derive_key(salt)
            cipher = Fernet(key)

            # Chiffrer le nom de fichier original
            original_name = file_path.name.encode('utf-8')
            encrypted_name = cipher.encrypt(original_name)

            # Chiffrer les données
            encrypted_data = cipher.encrypt(file_data)

            # Construire le contenu : [salt][4 bytes taille nom chiffré][nom chiffré][données]
            name_length = struct.pack('>I', len(encrypted_name))  # 4 bytes big-endian

            # Nom du fichier de sortie : UUID aléatoire
            encrypted_file_path = file_path.parent / (str(uuid.uuid4()) + '.enc')

            with open(encrypted_file_path, 'wb') as f:
                f.write(salt + name_length + encrypted_name + encrypted_data)

            os.remove(file_path)
            print(f"✓ Chiffré : {file_path.name}  →  {encrypted_file_path.name}")
            return True

        except Exception as e:
            print(f"✗ Erreur lors du chiffrement de {file_path}: {str(e)}")
            return False

    def decrypt_file(self, file_path):
        """
        Déchiffrer un fichier .enc.
        Relit le nom original depuis le header pour restaurer le fichier.
        """
        file_path = Path(file_path)

        # Bloquer le déchiffrement d'un fichier non-.enc
        if file_path.suffix != '.enc':
            print(f"⚠ Ignoré (pas un fichier chiffré) : {file_path}")
            return False

        try:
            with open(file_path, 'rb') as f:
                raw = f.read()

            # Lire le salt
            salt = raw[:SALT_SIZE]
            offset = SALT_SIZE

            # Lire la longueur du nom chiffré (4 bytes)
            name_length = struct.unpack('>I', raw[offset:offset + 4])[0]
            offset += 4

            # Lire le nom chiffré
            encrypted_name = raw[offset:offset + name_length]
            offset += name_length

            # Le reste = données chiffrées
            encrypted_data = raw[offset:]

            key = self._derive_key(salt)
            cipher = Fernet(key)

            # Déchiffrer le nom original
            original_name = cipher.decrypt(encrypted_name).decode('utf-8')

            # Déchiffrer les données
            decrypted_data = cipher.decrypt(encrypted_data)

            # Restaurer le fichier avec son nom original
            decrypted_file_path = file_path.parent / original_name

            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)

            os.remove(file_path)
            print(f"✓ Déchiffré : {file_path.name}  →  {original_name}")
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
        skipped_count = 0

        files = list(directory.rglob('*') if recursive else directory.iterdir())
        for file_path in files:
            if not file_path.is_file():
                continue
            if file_path.suffix == '.enc':
                print(f"⚠ Ignoré (déjà chiffré) : {file_path.name}")
                skipped_count += 1
                continue
            file_count += 1
            if self.encrypt_file(file_path):
                success_count += 1

        print("-" * 50)
        print(f"Résultat : {success_count}/{file_count} fichiers chiffrés", end="")
        if skipped_count:
            print(f", {skipped_count} ignoré(s) car déjà chiffré(s)", end="")
        print()

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

        files = list(directory.rglob('*') if recursive else directory.iterdir())
        for file_path in files:
            if file_path.is_file() and file_path.suffix == '.enc':
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