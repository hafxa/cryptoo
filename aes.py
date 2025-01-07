'''This is my implementation of the AES encryption algorithm in python
    I want to emphasise that this was purely an exercise in understanding the algorithm'''
from aes_key import AESKeyExpansion
import numpy
import argparse 


NK = 4 #We'll start with 128bit 
NR = 10 #This indicates the number of key expansion rounds we need


sbox = [[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]


inv_s_box = [[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
            [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
            [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
            [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
            [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
            [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
            [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
            [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
            [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
            [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
            [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
            [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
            [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
            [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
            [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
        ]

mix_column_matrix = [[2,3,1,1],
                     [1,2,3,1],
                     [1,1,2,3],
                     [3,1,1,2]]

inv_mix_columns_matrix = [
        [0xE, 0xB, 0xD, 0x9],
        [0x9, 0xE, 0xB, 0xD],
        [0xD, 0x9, 0xE, 0xB],
        [0xB, 0xD, 0x9, 0xE]]



#To the sane mind the below code may not make sense, but please bear with me
def correct_list(word):#
    new_list = []
    for j in range(0,7,2):
        for i in range(j,j+25,8):
            new_list.append(word[i:i+2].zfill(2))
    return new_list

def pt_to_state(plaintext):
    arr = [hex(ord(word)).removeprefix('0x').zfill(2) for word in plaintext]
    s = numpy.array(arr)
    shape = (4,4)
    return s.reshape(shape)

def hex_to_state(input):
    if isinstance(input,list) or isinstance(input,numpy.ndarray) :
        arr = input
    else:
        arr = correct_list(input)
    s = numpy.array(arr)
    shape = (4,4)
    return s.reshape(shape)

def state_to_string(state):
    if isinstance(state,numpy.ndarray):
        s = ''
        for i in range(4):
            for j in range(4):
                s+=state[j][i]
        return s
            
    else:
        return "Error - trying to convert not-a-state into a string"


def roundKey_to_state(roundKey):
    s = ''
    for word in roundKey:
        s+=word
    return hex_to_state(s)
        

def add_round_key(state1,state2):
    #state1 should be the pt and state2 should be roundkey
    new_state = []
    for i in range(4):
        for j in range(4):
            new_state.append((hex(int(state1[i][j],16) ^ int(state2[i][j],16)).removeprefix('0x').zfill(2)))
    return hex_to_state(new_state)

def sub_bytes(state):
    #so same thing as before really
    new_state = []
    for i in state:
        for word in i:
            row,column = int(word[0],16),int(word[1],16)
            new_state.append(hex(sbox[row][column]))
    return hex_to_state(new_state)

def shift_row(state):
    for i in range(1,4):
        state[i] = numpy.roll(state[i],-i)
    return state


#This obviously isn't my code, but it's used to multiply 
#two bytes in galois field. Pretty cool stuff.
def gm(a,b):
    p = 0 #Product accumulator
    while a!=0 and b!=0: #iterate over the numbers
        if (b & 1): #if lsb is 1, xor product
            p^=a
        if (a & 0x80): #checks if the field is 8 elements
            a=(a<<1)^0x11b 
        else:
            a<<=1
        b>>=1
    return p

def mix_column(state,matrix):
    sum = 0
    new_state = ''
    k = 0
    for column in range(4):
        for row in range(4):
            sum = 0
            for k in range(4):
                sum^=gm(int(state[k][column],16),matrix[row][k])
            new_state+=hex(sum).removeprefix('0x').zfill(2)
    return hex_to_state(new_state)


def inv_shift_rows(state):
    for i in range(1,4):
        state[i] = numpy.roll(state[i],i+4)
    return state


def inv_sub_bytes(state):
    new_state = []
    for i in state:
        for word in i:
            row,column = int(word[0],16),int(word[1],16)
            new_state.append(hex(inv_s_box[row][column]))
    return hex_to_state(new_state)


def round_key(key):
    string = ''.join(key)
    return hex_to_state(string)


def encrypt(plaintext,key):
    state = hex_to_state(plaintext)
    state1 = round_key(key[0])
    state = add_round_key(state,state1)
    i = 1
    while i < 10:
        state2 = round_key(key[i])
        state = add_round_key(mix_column(shift_row(sub_bytes(state)),mix_column_matrix),state2) 
        i+=1
    else:
        state2 = round_key(key[i])
        final_state = add_round_key(shift_row(sub_bytes(state)),state2)
    return state_to_string(final_state)



def decrypt(ciphertext,key):
    #SO in round 0, we only xor with round key
    state = hex_to_state(ciphertext)
    state1 = round_key(key[10])
    state = add_round_key(state,state1)
    i = 9
    while i > 0:
        state2 = round_key(key[i])
        state = mix_column(add_round_key(inv_shift_rows(inv_sub_bytes(state)),state2),inv_mix_columns_matrix) 
        i-=1
    else:
        state2 = round_key(key[i])
        final_state = add_round_key(inv_shift_rows(inv_sub_bytes(state)),state2)
    return state_to_string(final_state)


def word_split(word):
    list = []
    if len(word)%32==0:
        for block in range(0,len(word),32):
            list.append(word[block:block+32])
    return list


def ecb(word,key):
    #we will start with ecb because it's the simplest
    #brb gotta research it lol
    word_list = word_split(word)
    for word in word_list:
        encrypt(word,key)
    return word_list


def cbc_encrypt(word,key,iv):
    #Encrypting cbc mode
    word_list = word_split(word)
    word_list[0] = encrypt(add_round_key(hex_to_state(word_list[0]),hex_to_state(iv)),key)
    for i in range(1,len(word_list)):
        new_pt = add_round_key(hex_to_state(word_list[i]),hex_to_state(word_list[i-1]))
        word_list[i] = encrypt(new_pt,key)
    return word_list


def cbc_decrypt(ciphertext,key,iv):
    #Decrypting cbc mode
    word_list = word_split(ciphertext)
    new_word = []
    new_word.append(add_round_key(hex_to_state(decrypt(word_list[0],key)),hex_to_state(iv)))
    for i in range(1,len(word_list)):
        new_word.append(state_to_string(add_round_key(hex_to_state(decrypt(word_list[i],key))),hex_to_state(word_list[i-1])))
    return new_word

        
def ctr_encrypt(word,key,counter):
    #Implementing ctr mode..also works for decryption funnily enough
    word_list = word_split(word)
    for i in range(len(word_list)):
        word_list[i] = state_to_string(add_round_key(hex_to_state(word_list[i]),hex_to_state(encrypt(hex_to_state(counter),key))))
        counter = hex(int(counter,16)+1).removeprefix('0x')
    return word_list

def pad(word):
    #This is supposed to be PCKS#7 padding...if there's a mistake please let me know
    if len(word)%32==0:
        #If the input length is a multiple of 32 then we pad a whole block 
        word+=('10'*16)
        return word
    difference = (32 - (len(word)%32))//2
    word+=(hex(difference).removeprefix('0x').zfill(2)*difference)
    return word


def unpad(text):
    #I spent exactly 2 minutes on this and it shows
    #we know that all inputs are padded, so it makes it a lot easier to remove padding
    num = int(text[-2:],16)*2
    return text[:(len(text)-num)]


parser = argparse.ArgumentParser(
                                description='This is a simple implementation of AES in python',
                                usage='input key iv/ctr (optionally) -e|-d')

parser.add_argument('input',help='The input to be encrypted/decrypted')
parser.add_argument('key', help='The key used to encrypt/decrypt')
parser.add_argument('iv',nargs='?', help='Only for cbc/ctr')
parser.add_argument('-e','--encrypt',action='store_true',help='Flag for encryption')
parser.add_argument('-d','--decrypt',action='store_true',help='Flag for decryption')
parser.add_argument('--mode', choices=['ecb', 'cbc', 'ctr'], required=True, help='Block cipher mode to use (ecb, cbc, or ctr)')


args = parser.parse_args()

if len(args.key) != 32:
    parser.error('Key must be a 128-bit hexadecimal string (32 hex characters).')
if len(args.input) % 32 != 0 and args.decrypt:
    parser.error('Ciphertext length must be a multiple of 32 (16 bytes) for decryption.')
else:
    key = AESKeyExpansion(NK,NR,args.key).key_exp()
    if args.mode == 'ecb':
        if args.encrypt:
            print(f"The ciphertext is: {ecb(pad(args.input), key)}")
        elif args.decrypt:
            print(f"The plaintext is: {unpad(ecb(args.input, key))}")
    elif args.mode == 'cbc':
        if not args.iv:
            parser.error('IV is required for CBC mode.')
        if args.encrypt:
            print(f"The ciphertext is: {cbc_encrypt(pad(args.input), key, args.iv)}")
        elif args.decrypt:
            print(f"The plaintext is: {unpad(cbc_decrypt(args.input, key, args.iv))}")
    elif args.mode == 'ctr':
        if not args.iv:
            parser.error('Counter is required for CTR mode.')
        print(f"The text is: {ctr_encrypt(pad(args.input), key, args.iv)}")