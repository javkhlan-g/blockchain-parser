    # -*- coding: utf-8 -*-
#
# Blockchain parser
# Copyright (c) 2015-2019 Denis Leonov <466611@gmail.com>
#

import os
#import datetime
import hashlib
from datetime import datetime
import base58 as base58
import binascii


def startsWithOpNCode(pub):
  try:
    intValue = int(pub[0:2], 16)
    if intValue >= 1 and intValue <= 75:
      return True
  except:
    pass
  return False

def publicKeyDecoder(pub):
  if pub.lower().startswith('76a914'):
    pub = pub[6:-4]
    result = (b'\x00') + binascii.unhexlify(pub)
    h5 = hashlib.sha256(result)
    h6 = hashlib.sha256(h5.digest())
    result += h6.digest()[:4]
    return base58.b58encode(result)
  elif pub.lower().startswith('a9'):
    return ""
  elif startsWithOpNCode(pub):
    pub = pub[2:-2]
    h3 = hashlib.sha256(binascii.unhexlify(pub))
    h4 = hashlib.new('ripemd160', h3.digest())
    result = (b'\x00') + h4.digest()
    h5 = hashlib.sha256(result)
    h6 = hashlib.sha256(h5.digest())
    result += h6.digest()[:4]
    return base58.b58encode(result)
  return ""

def publicKeyDecode(pub):
    pub = pub[2:-2]
    hash1 = hashlib.sha256(binascii.unhexlify(pub))
    hash2 = hashlib.new('ripemd160', hash1.digest())
    padded = (b'\x00') + hash2.digest()
    hash3 = hashlib.sha256(padded)
    hash4 = hashlib.sha256(hash3.digest())
    padded += hash4.digest()[:4]
    return base58.b58encode(padded)

def HexToInt(s):
    t = ''
    if s == '':
        r = 0
    else:
        t = '0x' + s
        r = int(t,16)
    return r
    
def reverse(input):
    L = len(input)
    if (L % 2) != 0:
        return None
    else:
        Res = ''
        L = L // 2
        for i in range(L):
            T = input[i*2] + input[i*2+1]
            Res = T + Res
            T = ''
        return (Res);

def merkle_root(lst): # https://gist.github.com/anonymous/7eb080a67398f648c1709e41890f8c44
    sha256d = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
    hash_pair = lambda x, y: sha256d(x[::-1] + y[::-1])[::-1]
    if len(lst) == 1: return lst[0]
    if len(lst) % 2 == 1:
        lst.append(lst[-1])
    return merkle_root([hash_pair(x,y) for x, y in zip(*[iter(lst)]*2)])

dirA = 'C:/dev/blockchain-parser/' # Directory where blk*.dat files are stored
#dirA = sys.argv[1]
dirB = 'C:/dev/blockchain-parser/hash/' # Directory where to save parsing results
#dirA = sys.argv[2]

fList = os.listdir(dirA)
fList = [x for x in fList if (x.endswith('.dat') and x.startswith('blk'))]
fList.sort()

for i in fList:
    nameSrc = i
    nameRes = nameSrc.replace('.dat','.txt')
    resList = []
    resList = []
    a = 0
    t = dirA + nameSrc
    resList.append('Start ' + t + ' in ' + str(datetime.now()))
    print ('Start ' + t + ' in ' + str(datetime.now()))
    f = open(t,'rb')
    tmpHex = ''
    fSize = os.path.getsize(t)

    while (fSize - f.tell() > 80):
	print('read bytes ' + str(f.tell()) + ' of ' + str(fSize)+ ' , ('+ str(round((100.00 * f.tell()/fSize),2))+' %)')
        for j in range(4):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        resList.append('Block size = ' + str(int(tmpHex,16)) + ' bytes')
        tmpHex = ''
        tmpPos3 = f.tell()
        while f.tell() != tmpPos3 + 80:
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = tmpHex + b
        tmpHex = tmpHex.decode('hex')
        tmpHex = hashlib.new('sha256', tmpHex).digest()
        tmpHex = hashlib.new('sha256', tmpHex).digest()
        tmpHex = tmpHex.encode('hex')
        tmpHex = tmpHex.upper()
        tmpHex = reverse(tmpHex)
        resList.append('SHA256 hash of the current block hash = ' + tmpHex)
        f.seek(tmpPos3,0)
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        resList.append('Version number = ' + tmpHex)
        tmpHex = ''
        for j in range(32):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        resList.append('SHA256 hash of the previous block hash = ' + tmpHex)
        tmpHex = ''
        for j in range(32):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        resList.append('MerkleRoot hash = ' + tmpHex)
        MerkleRoot = tmpHex
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        resList.append('Time stamp  ' + datetime.utcfromtimestamp(int(tmpHex,16)).strftime('%Y-%m-%d %H:%M:%S'))
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        resList.append('nBits = ' + str(int(tmpHex,16)))
        tmpHex = ''
        for j in range(4):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        resList.append('Nonce ' + str(int(tmpHex,16)))
        tmpHex = ''
        b = f.read(1)
        bInt = int(b.encode('hex'),16)
        c = 0
        if bInt < 253:
            c = 1
            tmpHex = b.encode('hex').upper()
        if bInt == 253: c = 3
        if bInt == 254: c = 5
        if bInt == 255: c = 9
        for j in range(1,c):
            b = f.read(1)
            b = b.encode('hex').upper()
            tmpHex = b + tmpHex
        txCount = int(tmpHex,16)
        resList.append('Transactions count = ' + str(txCount))
        resList.append('')
        tmpHex = ''
        tmpPos1 = 0
        tmpPos2 = 0
        RawTX = ''
        tx_hashes = []
        for k in range(txCount):
            tmpPos1 = f.tell()
            for j in range(4):
                b = f.read(1)
                b = b.encode('hex').upper()
                tmpHex = b + tmpHex
            resList.append('transactionVersionNumber = ' + tmpHex)
            RawTX = reverse(tmpHex)
            tmpHex = ''
            b = f.read(1)
            tmpB = b.encode('hex').upper()
            bInt = int(b.encode('hex'),16)
            Witness = False
            if bInt == 0:
                tmpB = ''
                c = 0
                c = f.read(1)
                bInt = int(c.encode('hex'),16)
                c = 0
                c = f.read(1)
                bInt = int(c.encode('hex'),16)
                tmpB = c.encode('hex').upper()
                Witness = True
                resList.append('Witness activated >>')
            c = 0
            if bInt < 253:
                c = 1
                tmpHex = hex(bInt)[2:].upper().zfill(2)
                tmpB = ''
            if bInt == 253: c = 3
            if bInt == 254: c = 5
            if bInt == 255: c = 9
            for j in range(1,c):
                b = f.read(1)
                b = b.encode('hex').upper()
                tmpHex = b + tmpHex
            inCount = int(tmpHex,16)
            resList.append('Inputs count = ' + tmpHex)
            tmpHex = tmpHex + tmpB
            RawTX = RawTX + reverse(tmpHex)
            tmpHex = ''
            for m in range(inCount):
                for j in range(32):
                    b = f.read(1)
                    b = b.encode('hex').upper()
                    tmpHex = b + tmpHex
                resList.append('TX from hash = ' + tmpHex)
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                for j in range(4):
                    b = f.read(1)
                    b = b.encode('hex').upper()
                    tmpHex = b + tmpHex
                    resList.append('N output = ' + str(int(tmpHex,16)))
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                b = f.read(1)
                tmpB = b.encode('hex').upper()
                bInt = int(b.encode('hex'),16)
                c = 0
                if bInt < 253:
                    c = 1
                    tmpHex = b.encode('hex').upper()
                    tmpB = ''
                if bInt == 253: c = 3
                if bInt == 254: c = 5
                if bInt == 255: c = 9
                for j in range(1,c):
                    b = f.read(1)
                    b = b.encode('hex').upper()
                    tmpHex = b + tmpHex
                scriptLength = int(tmpHex,16)
                tmpHex = tmpHex + tmpB
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''

                for j in range(scriptLength):
                    b = f.read(1)
                    b = b.encode('hex').upper()
                    tmpHex = tmpHex + b
                resList.append('Input script = ' + tmpHex)
                # check coinbase or regular transaction. coinbase always 1
                if txCount > 1 :
                    walletAddress = publicKeyDecoder(tmpHex)
                    resList.append('sender address = ' + walletAddress)
                RawTX = RawTX + tmpHex
                tmpHex = ''
                for j in range(4):
                    b = f.read(1)
                    b = b.encode('hex').upper()
                    tmpHex = tmpHex + b
                resList.append('sequenceNumber = ' + str(int(tmpHex,16)) )
                RawTX = RawTX + tmpHex
                tmpHex = ''
            b = f.read(1)
            tmpB = b.encode('hex').upper()
            bInt = int(b.encode('hex'),16)
            c = 0
            if bInt < 253:
                c = 1
                tmpHex = b.encode('hex').upper()
                tmpB = ''
            if bInt == 253: c = 3
            if bInt == 254: c = 5
            if bInt == 255: c = 9
            for j in range(1,c):
                b = f.read(1)
                b = b.encode('hex').upper()
                tmpHex = b + tmpHex
            outputCount = int(tmpHex,16)
            tmpHex = tmpHex + tmpB
            resList.append('Outputs count = ' + str(outputCount))
            RawTX = RawTX + reverse(tmpHex)
            tmpHex = ''
            for m in range(outputCount):
                for j in range(8):
                    b = f.read(1)
                    b = b.encode('hex').upper()
                    tmpHex = b + tmpHex
                Value = tmpHex
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                b = f.read(1)
                tmpB = b.encode('hex').upper()
                bInt = int(b.encode('hex'),16)
                c = 0
                if bInt < 253:
                    c = 1
                    tmpHex = b.encode('hex').upper()
                    tmpB = ''
                if bInt == 253: c = 3
                if bInt == 254: c = 5
                if bInt == 255: c = 9
                for j in range(1,c):
                    b = f.read(1)
                    b = b.encode('hex').upper()
                    tmpHex = b + tmpHex
                scriptLength = int(tmpHex,16)
                tmpHex = tmpHex + tmpB
                RawTX = RawTX + reverse(tmpHex)
                tmpHex = ''
                for j in range(scriptLength):
                    b = f.read(1)
                    b = b.encode('hex').upper()
                    tmpHex = tmpHex + b
                resList.append('Value = ' + str(int(Value,16)))
                resList.append('Output script = ' + tmpHex)

                walletAddress = publicKeyDecode(tmpHex);
                resList.append('receiver address = ' + walletAddress)

                RawTX = RawTX + tmpHex
                tmpHex = ''
            if Witness == True:
                for m in range(inCount):
                    tmpHex = ''
                    b = f.read(1)
                    bInt = int(b.encode('hex'),16)
                    c = 0
                    if bInt < 253:
                        c = 1
                        tmpHex = b.encode('hex').upper()
                    if bInt == 253: c = 3
                    if bInt == 254: c = 5
                    if bInt == 255: c = 9
                    for j in range(1,c):
                        b = f.read(1)
                        b = b.encode('hex').upper()
                        tmpHex = b + tmpHex
                    WitnessLength = int(tmpHex,16)
                    tmpHex = ''
                    for j in range(WitnessLength):
                        tmpHex = ''
                        b = f.read(1)
                        bInt = int(b.encode('hex'),16)
                        c = 0
                        if bInt < 253:
                            c = 1
                            tmpHex = b.encode('hex').upper()
                        if bInt == 253: c = 3
                        if bInt == 254: c = 5
                        if bInt == 255: c = 9
                        for j in range(1,c):
                            b = f.read(1)
                            b = b.encode('hex').upper()
                            tmpHex = b + tmpHex
                        WitnessItemLength = int(tmpHex,16)
                        tmpHex = ''
                        for p in range(WitnessItemLength):
                            b = f.read(1)
                            b = b.encode('hex').upper()
                            tmpHex = b + tmpHex
                        resList.append('Witness ' + str(m) + ' ' + str(j) + ' ' + str(WitnessItemLength) + ' ' + tmpHex)
                        tmpHex = ''
            Witness = False
            for j in range(4):
                b = f.read(1)
                b = b.encode('hex').upper()
                tmpHex = b + tmpHex
            resList.append('Lock time = ' + tmpHex)
            RawTX = RawTX + reverse(tmpHex)
            tmpHex = ''
            tmpHex = RawTX
            tmpHex = tmpHex.decode('hex')
            tmpHex = hashlib.new('sha256', tmpHex).digest()
            tmpHex = hashlib.new('sha256', tmpHex).digest()
            tmpHex = tmpHex.encode('hex')
            tmpHex = tmpHex.upper()
            tmpHex = reverse(tmpHex)
            resList.append('TX hash = ' + tmpHex)
            # test for first reqular transaction
            #if tmpHex == 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16'.upper() :
            #    txJson = publicKeyDecode();
            #    resList.append('Tx detail = ' + txJson)
            tx_hashes.append(tmpHex)
            tmpHex = ''
            resList.append('')
            RawTX = ''
        a += 1
        tx_hashes = [h.decode('hex') for h in tx_hashes]
        if MerkleRoot != '0000000000000000000000000000000000000000000000000000000000000000':
            tmpHex = merkle_root(tx_hashes).encode('hex').upper()
            if tmpHex != MerkleRoot:
                print ('Merkle roots does not match! >',MerkleRoot,tmpHex)
            tmpHex = ''
        else:
            break
    f.close()
    f = open(dirB + nameRes,'w')
    for j in resList:
        f.write(j + '\n')
    f.close()
nameSrc = ''
nameRes = ''
dirA= ''
dirB = ''
tmpC = ''
resList = []
fList = []