import time
from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA384
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss


from Crypto import Random

def DSA_sign(key, h):
        signer = DSS.new(key, 'deterministic-rfc6979')
        return signer.sign(h)

def DSA_verify(sign, key, h):
    try:
        verifier = DSS.new(key, 'deterministic-rfc6979')
        verifier.verify(h, sign)
    except ValueError:
        print ('The message is not authentic')

def hashed_message(hash_type, message):
    if hash_type =='SHA-1':
        h = SHA.new(bytes(message, 'utf-8'))
    elif hash_type =='SHA-224':
        h = SHA256.new(bytes(message, 'utf-8'))
    elif hash_type =='SHA-256':
        h = SHA256.new(bytes(message, 'utf-8'))
    elif hash_type =='SHA-384':
        h = SHA384.new(bytes(message, 'utf-8'))
    else:
        h = SHA256.new(bytes(message, 'utf-8'))

    return h

        
def DSA_times(tests_information):
    key_param = [line.strip('\n') for line in open("dsa_key_params.txt")]
    p=int(key_param[0], 16)
    q=int(key_param[1], 16)
    g=int(key_param[2], 16)
    x=int(key_param[3], 16)
    y=int(key_param[4], 16)

    key= DSA.construct([y, g, p, q, x]) #Construccion de la llave
    sign_times = []
    verify_times = []
    print(key)
    for t in tests_information:
        [hash_type, message] = t.split(',')
        h = hashed_message(hash_type, message)
            
        #sign
        start_time = time.perf_counter()
        sign = DSA_sign(key, h)
        elapsed_time = time.perf_counter() - start_time
        sign_times.append(elapsed_time)
        
        #verification
        start_time = time.perf_counter()
        DSA_verify(sign, key, h)
        elapsed_time = time.perf_counter() - start_time
        verify_times.append(elapsed_time)

    return [sign_times, verify_times]


def ECDSA_sign(key, h):
        signer = DSS.new(key, 'deterministic-rfc6979')
        return signer.sign(h)

def ECDSA_verify(sign, key, h):
    try:
        verifier = DSS.new(key, 'deterministic-rfc6979')
        verifier.verify(h, sign)
    except ValueError:
        print ('The message is not authentic')

        
def ECDSA_times(tests_information):
    key_params = [line.strip('\n') for line in open("ECDSA_key_params.txt")]
    q=int(key_params[0], 16)
    x=int(key_params[1], 16)
    ux=int(key_params[2], 16)
    uy=int(key_params[3], 16)
    key=ECC.construct(curve='NIST P-521', d=x, point_x=ux, point_y=uy)
    sign_times = []
    verify_times = []
    for t in tests_information:
        [hash_type, message] = t.split(',')
        h = hashed_message(hash_type, message)

            
        #sign
        start_time = time.perf_counter()
        sign = ECDSA_sign(key, h)
        elapsed_time = time.perf_counter() - start_time
        sign_times.append(elapsed_time)
        
        #verification
        start_time = time.perf_counter()
        ECDSA_verify(sign, key, h)
        elapsed_time = time.perf_counter() - start_time
        verify_times.append(elapsed_time)

    return [sign_times, verify_times]



def RSA_PSS_sign(key, message):
        h = SHA256.new(message)
        signer = PKCS1_PSS.new(key)
        return signer.sign(h)

def RSA_PSS_verify(message, key, sign):
    try:
        h = SHA256.new(message)
        verifier = pss.new(key)
        verifier.verify(h, sign)
    except ValueError:
        print ('The message is not authentic')

def RSA_PSS_times():
    sign_times = []
    verify_times = []
    for i in range(0, 11):
        message = Random.get_random_bytes(64)
        key = RSA.generate(1024)        
        # To sign
        start_time = time.perf_counter()
        sign = RSA_PSS_sign(key, message)
        elapsed_time = time.perf_counter() - start_time
        sign_times.append(elapsed_time)


        # To verify
        start_time = time.perf_counter()
        RSA_PSS_verify(message, key, sign)
        elapsed_time = time.perf_counter() - start_time

        verify_times.append(elapsed_time)

    return [verify_times, sign_times]

def print_cipher_times(DSA, ECDSA, RSA_PSS):
    number_of_vectors = len(DSA)
    DSA_total_time = 0
    ECDSA_total_time = 0
    RSA_PSS_total_time = 0

    print('\n\t#------------------------------------------------------------------------------------------------------#')
    print('\t|                                                     Cifrado                                          |')             
    print('\t#------------------------------------------------------------------------------------------------------#')
    print('\t|     No. Vector      |          DSA          |          ECDSA          |          RSA_PSS             |')
    print('\t#------------------------------------------------------------------------------------------------------#')
    for t in range(number_of_vectors):
        print('\t|     vector ',t ,'      |\t      {:0.6f}        |\t      {:0.6f}          |\t      {:0.6f}         |'.format(DSA[t], ECDSA[t],RSA_PSS[t]))
        print('\t#------------------------------------------------------------------------------------------------------#')
        DSA_total_time += DSA[t]
        ECDSA_total_time += ECDSA[t]
        RSA_PSS_total_time += RSA_PSS[t]

    print('\t|       Promedio      |\t       {:0.6f}       |\t       {:0.6f}         |\t       {:0.6f}        |'.format(DSA_total_time/number_of_vectors, ECDSA_total_time/number_of_vectors,RSA_PSS_total_time/number_of_vectors))
    print('\t#------------------------------------------------------------------------------------------------------#\n')

def print_descipher_times(DSA, ECDSA, RSA_PSS):
    number_of_vectors = len(DSA)
    DSA_total_time = 0
    ECDSA_total_time = 0
    RSA_PSS_total_time = 0

    print('\n\t#------------------------------------------------------------------------------------------------------#')
    print('\t|                                            Descifrado                                                |')             
    print('\t#------------------------------------------------------------------------------------------------------#')
    print('\t|     No. Vector      |          DSA          |          ECDSA          |          RSA_PSS             |')
    print('\t#------------------------------------------------------------------------------------------------------#')
    for t in range(number_of_vectors):
        print('\t|     vector ',t ,'      |\t      {:0.6f}        |\t      {:0.6f}          |\t      {:0.6f}         |'.format(DSA[t], ECDSA[t],RSA_PSS[t]))
        print('\t#------------------------------------------------------------------------------------------------------#')
        DSA_total_time += DSA[t]
        ECDSA_total_time += ECDSA[t]
        RSA_PSS_total_time += RSA_PSS[t]

    print('\t|       Promedio      |\t       {:0.6f}       |\t       {:0.6f}         |\t       {:0.6f}        |'.format(DSA_total_time/number_of_vectors, ECDSA_total_time/number_of_vectors,RSA_PSS_total_time/number_of_vectors))
    print('\t#------------------------------------------------------------------------------------------------------#\n')

def compare_signature_algorithms():
    tests_information = [line.strip('\n') for line in open("signature_vectors.txt" )]
    [sign_ECDSA_times, verify_ECDSA_times] = ECDSA_times(tests_information)
    [sign_DSA_times, verify_DSA_times] = ECDSA_times(tests_information)
    [sign_RSA_PSS_rimes, verify_RSA_PSS_times] = RSA_PSS_times()
    print_cipher_times(sign_DSA_times, sign_ECDSA_times, sign_RSA_PSS_rimes)
    print_descipher_times(verify_DSA_times, verify_ECDSA_times, verify_RSA_PSS_times)


