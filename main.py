import time
from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto.Hash import SHA3_256
from hash_vectors import *

def SHA1_ENCRYPT(plaintext):
    h = SHA.new()
    h.update(plaintext)

def SHA1_times(vectors):
    times = []
    for v in vectors:
        start_time = time.perf_counter()
        SHA1_ENCRYPT(v)
        elapsed_time = time.perf_counter() - start_time
        times.append(elapsed_time)
    return times


def SHA2_ENCRYPT(plaintext):
    h = SHA256.new()
    h.update(plaintext)

def SHA2_times(vectors):
    times = []
    for v in vectors:
        start_time = time.perf_counter()
        SHA2_ENCRYPT(v)
        elapsed_time = time.perf_counter() - start_time
        times.append(elapsed_time)
    return times

def SHA3_ENCRYPT(plaintext):
    h = SHA3_256.new()
    h.update(plaintext)

def SHA3_times(vectors):
    times = []
    for v in vectors:
        start_time = time.perf_counter()
        SHA3_ENCRYPT(v)
        elapsed_time = time.perf_counter() - start_time
        times.append(elapsed_time)
    return times

def compare_hash_algoritms():
    vectors = hash_vectors()
    sha1_times = SHA1_times(vectors)
    sha2_times = SHA2_times(vectors)
    sha3_times = SHA3_times(vectors)
    print_hash_times(sha1_times, sha2_times, sha3_times)

def print_hash_times(sha1, sha2, sha3):
    number_of_vectors = len(sha1)
    sha1_total_time = 0
    sha2_total_time = 0
    sha3_total_time = 0
    

    print('\n\t#----------------------------------------------------------------------------------------------------------------------------#')
    print('\t|                                                   Message Digest                                                           |')             
    print('\t#----------------------------------------------------------------------------------------------------------------------------#')
    print('\t|     No. Vector          |               SHA-1               |              SHA-2              |             SHA-3           |')
    print('\t#----------------------------------------------------------------------------------------------------------------------------#')


    for t in range(len(sha1)):
        print('\t|     vector ',t ,'         |            {:0.6f}             |            {:0.6f}             |            {:0.6f}           |'.format(sha1[t], sha2[t], sha3[t]))
        print('\t#----------------------------------------------------------------------------------------------------------------------------#')
        sha1_total_time += sha1[t]
        sha2_total_time += sha2[t]
        sha3_total_time += sha3[t]

    print('\t|       Promedio           |            {:0.6f}             |            {:0.6f}             |            {:0.6f}          |'.format(sha1_total_time/number_of_vectors, sha2_total_time/number_of_vectors,sha3_total_time/number_of_vectors))
    print('\t#----------------------------------------------------------------------------------------------------------------------------#\n')


compare_hash_algoritms()