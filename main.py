from hash_algorithms import compare_hash_algoritms
from signature_algorithms import compare_signature_algorithms
from encrypt_algoritms import compare_encrypt_algoritms
import os

compare_hash_algoritms()
input("Press <Enter> to continue...")
os.system('cls' if os.name == 'nt' else 'clear')
compare_signature_algorithms()
input("Press <Enter> to continue...")
os.system('cls' if os.name == 'nt' else 'clear')
compare_encrypt_algoritms()
