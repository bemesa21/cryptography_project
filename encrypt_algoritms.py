from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

import time

def AES_test():
    lines  = [line.rstrip('\n') for line in open("test_vectors_AES.txt")]
    keys   = [line[31:] for line in lines if 'key=' in line]
    plain  = [line[31:] for line in lines if 'plain=' in line]
    return [ [keys[i], plain[i]] for i in range( len(keys) ) ]

def AES_CBC_cypher(key, plaintext, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.encrypt(plaintext)
    return msg

def AES_CBC_decipher(key, encrypthed_message, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher.decrypt(encrypthed_message)


def AES_CBC_times(vectors):
    cypher_times = []
    desc_times = []
    iv =  b"\x00"*16

    for v in vectors:
        
        start_time = time.perf_counter()
        cypher_msg = AES_CBC_cypher(bytearray.fromhex(v[0]), bytearray.fromhex(v[1]), iv)
        elapsed_time = time.perf_counter() - start_time
        cypher_times.append(elapsed_time)

        start_time = time.perf_counter()
        AES_CBC_decipher(bytearray.fromhex(v[0]), cypher_msg, iv)
        elapsed_time = time.perf_counter() - start_time
        desc_times.append(elapsed_time)
    return [cypher_times, desc_times]


def AES_EBC_cypher(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    msg = cipher.encrypt(plaintext)
    return msg

def AES_EBC_decipher(key, encrypthed_message):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher.decrypt(encrypthed_message)


def AES_EBC_times(vectors):
    cypher_times = []
    desc_times = []
    iv =  b"\x00"*16

    for v in vectors:
        
        start_time = time.perf_counter()
        cypher_msg = AES_EBC_cypher(bytearray.fromhex(v[0]), bytearray.fromhex(v[1]))
        elapsed_time = time.perf_counter() - start_time
        cypher_times.append(elapsed_time)

        start_time = time.perf_counter()
        AES_EBC_decipher(bytearray.fromhex(v[0]), cypher_msg)
        elapsed_time = time.perf_counter() - start_time
        desc_times.append(elapsed_time)
    return [cypher_times, desc_times]

def compare_encrypt_algoritms():
    vectors = AES_test()
    [AES_CBC_en_time, AES_CBC_des_time] = AES_CBC_times(vectors)
    [AES_EBC_en_time, AES_EBC_des_time] = AES_EBC_times(vectors)
    [OAEP_en_time, OAEP_des_time] = RSA_OACP_times()

    print_encrypt_times(AES_EBC_en_time, AES_CBC_en_time, OAEP_en_time)
    print_decrypt_times(AES_CBC_des_time, AES_EBC_des_time, OAEP_des_time)



def RSA_OACP_encrypt(key, message):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)

def RSA_OACP_decrypt(message, key, ciphertext):
    cipher = PKCS1_OAEP.new(key)
    cipher.decrypt(ciphertext)


def RSA_OACP_times():
    sign_times = []
    verify_times = []
    for i in range(0, 72):
        message = Random.get_random_bytes(64)
        key = RSA.generate(1024)        
        # To sign
        start_time = time.perf_counter()
        sign = RSA_OACP_encrypt(key, message)
        elapsed_time = time.perf_counter() - start_time
        sign_times.append(elapsed_time)


        # To verify
        start_time = time.perf_counter()
        RSA_OACP_decrypt(message, key, sign)
        elapsed_time = time.perf_counter() - start_time

        verify_times.append(elapsed_time)

    return [verify_times, sign_times]

def print_encrypt_times(EBC, CBC, OAPC):
    number_of_vectors = len(EBC)
    EBC_total_time = 0
    CBC_total_time = 0
    OAPC_total_time = 0

    print('\n\t#---------------------------------------------------------------------------------------------------------#')
    print('\t|                                              Cifrado                                                        |')             
    print('\t#-------------------------------------------------------------------------------------------------------------#')
    print('\t|     No. Vector      |          AES_EBC          |          AES_CBC          |          RSA_OAEP             |')
    print('\t#-------------------------------------------------------------------------------------------------------------#')
    for t in range(number_of_vectors):
        print('\t|     vector ',t ,'      |\t      {:0.6f}        |\t      {:0.6f}          |\t      {:0.6f}         |'.format(EBC[t], CBC[t],OAPC[t]))
        print('\t#---------------------------------------------------------------------------------------------------------#')
        EBC_total_time += EBC[t]
        CBC_total_time += CBC[t]
        OAPC_total_time += OAPC[t]

    print('\t|       Promedio      |\t       {:0.6f}       |\t       {:0.6f}         |\t       {:0.6f}        |'.format(EBC_total_time/number_of_vectors, CBC_total_time/number_of_vectors,OAPC_total_time/number_of_vectors))
    print('\t#------------------------------------------------------------------------------------------------------#\n')



def print_decrypt_times(EBC, CBC, OAPC):
    number_of_vectors = len(EBC)
    EBC_total_time = 0
    CBC_total_time = 0
    OAPC_total_time = 0

    print('\n\t#---------------------------------------------------------------------------------------------------------#')
    print('\t|                                             Descifrado                                                      |')             
    print('\t#-------------------------------------------------------------------------------------------------------------#')
    print('\t|     No. Vector      |          AES_EBC          |          AES_CBC          |          RSA_OAEP             |')
    print('\t#-------------------------------------------------------------------------------------------------------------#')
    for t in range(number_of_vectors):
        print('\t|     vector ',t ,'      |\t      {:0.6f}        |\t      {:0.6f}          |\t      {:0.6f}         |'.format(EBC[t], CBC[t],OAPC[t]))
        print('\t#---------------------------------------------------------------------------------------------------------#')
        EBC_total_time += EBC[t]
        CBC_total_time += CBC[t]
        OAPC_total_time += OAPC[t]

    print('\t|       Promedio      |\t       {:0.6f}       |\t       {:0.6f}         |\t       {:0.6f}        |'.format(EBC_total_time/number_of_vectors, CBC_total_time/number_of_vectors,OAPC_total_time/number_of_vectors))
    print('\t#------------------------------------------------------------------------------------------------------#\n')
