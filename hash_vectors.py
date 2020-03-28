def set1_input_vectors():
    return [bytearray(line.strip('\n'), "utf-8") for line in open( 'set1.txt' )]

def set1_programed_vectors():
    vector7 = bytearray("1234567890"*8, "utf-8")
    vector8 = bytearray("a"*1000000, "utf-8")
    return [vector7, vector8]

def set2_vectors():
    vectors = []
    for i in range(8, 1024, 8):
        vectors.append(b'\x00' * (i // 8))
    return vectors

def set3_vectors():
    vectors = []
    lines =[line for line in open( 'set3.txt' )]
    for l in lines:
        part1, part2, part3 = l.split(',')
        N = int(part1.split("*")[0])
        M = int(part3.split("*")[0])
        plaintext = (N * b"\x00") + bytearray.fromhex(part2) + (M * b"\x00")
        vectors.append( plaintext)
    return vectors

def hash_vectors():
    set1 = set1_input_vectors()
    set1_p = set1_programed_vectors()
    #set2 = set2_vectors()
    #set3 = set3_vectors()
    return set1 + set1_p #+ set2 + set3


