#/bin/zsh
import secrets

'''
KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
begin
word temp
    i = 0
    while (i < Nk)
    w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
    i = i+1
    end while
    i = Nk
    while (i < Nb * (Nr+1)]
        temp = w[i-1]
        if (i mod Nk = 0)
            temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
        else if (Nk > 6 and i mod Nk = 4)
            temp = SubWord(temp)
        end if
        w[i] = w[i-Nk] xor temp
        i = i + 1
    end while
end'''

class AESKeyExpansion:
    def __init__(self,NK,key):
        self.NK = NK
        self.key = key
        self.sbox =[[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
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
        
        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
                    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
                    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39]
        

    def word_list(self,key,word_list):
        for i in range(0,len(key),8):
            word_list.extend([key[i:i+8]])
        
        return word_list
    
    #rot word takes a word [a0,a1,a2,a3] and returns [a1,a2,a3,a4]
    def rot_word(self,word):
        a0 = word.pop(0)
        word.append(a0)
        return word

    #It takes a 4-byte word [a0,a1,a2,a3] and applies the s-box to obtain [b0,b1,b2,b3]
    def sub_word(self,word):
        new = []
        for i in word:
            row,column = int(i[0],16),int(i[1],16)
            new_word = self.sbox[row][column]
            new.append(hex(new_word))
        return new

    #Rcon[i] = [x^i-1,{0,0},{0,0},{0,0}]
    def r_con(self,i):
        return [hex(self.rcon[i]),'00','00','00']


    #Final step: w[i] xor w[i-1] xor w[i-4(Nk; 4 in this case)]

    def word_exp(self,word):
        new_list = []
        for i in range(0,8,2):
            new_list.append(word[i:i+2])
        return new_list

    def xor_func(self,arg1,arg2):
        result = []
        for i in range(4):
            xor_result = hex(int(arg1[i],16) ^ int(arg2[i],16))
            result.append(xor_result)
        return result

    def join_word(self,word_list):
        s=""
        for i in word_list:
            i = i.removeprefix('0x').zfill(2)
            s+=i
        return s

    def extra_rounds(self,prev,round):
        temp = self.sub_word(self.rot_word(prev))
        r_cons = self.r_con(round)
        return self.xor_func(temp,r_cons)
    
    def key_exp(self):
        if self.NK==4:
            NB,NR = 43,10
        elif self.NK==6:
            NB,NR = 51,12
        elif self.NK==8:
            NB,NR = 59,14
        else:
            exit('Wrong key length')
        temp = []
        arr = []
        arr.extend(self.word_list(self.key,[]))
        i = self.NK
        total = NB
        for i in range(self.NK,total+1):
            temp = self.word_exp(arr[i-1])
            if i%self.NK==0:
                temp = self.xor_func(self.sub_word(self.rot_word(temp)),self.r_con(i // self.NK))  
            elif i%self.NK==4 and self.NK>6: #for nk = 6 and nk = 8
                temp = self.sub_word(temp)
            temp = self.xor_func(temp,self.word_exp(arr[i - self.NK]))
            arr.append(self.join_word(temp))
        dict = {}
        i = 0
        for k in range(NR+1):
            dict[k] = [arr[i],arr[i+1],arr[i+2],arr[i+3]]
            i+=4
        return dict
            
       

    

key = AESKeyExpansion(8,'603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4').key_exp()
print(key)