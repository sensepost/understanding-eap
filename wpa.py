#!/usr/bin/env python3

# Original source https://nicholastsmith.wordpress.com/2016/11/15/wpa2-key-derivation-with-anaconda-python/

import hmac
from hashlib import pbkdf2_hmac, sha1, md5
from IPython import embed
 
def MakePMK(pwd, ssid):
  #Create the pairwise master key using 4096 iterations of hmac-sha1
  #to generate a 32 byte value
  pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)

  return pmk

def MakeAB(aNonce, sNonce, apMac, cliMac):
  #Make parameters for the generation of the PTK
  #aNonce:        The aNonce from the 4-way handshake
  #sNonce:        The sNonce from the 4-way handshake
  #apMac:         The MAC address of the access point
  #cliMac:        The MAC address of the client
  #return:        (A, B) where A and B are parameters for the generation of the PTK

  A = b"Pairwise key expansion"
  B = min(apMac, cliMac) + max(apMac, cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce)

  return (A, B)
 
def MakePTK(pmk, A, B):
  #Pseudo-random function for generation of
  #the pairwise transient key (PTK)
  #key:       The PMK
  #A:         b'Pairwise key expansion'
  #B:         The apMac, cliMac, aNonce, and sNonce concatenated
  #           like mac1 mac2 nonce1 nonce2
  #           such that mac1 < mac2 and nonce1 < nonce2
  #return:    The ptk

  #Number of bytes in the PTK
  nByte = 48
  i = 0
  R = b''
  #Each iteration produces 160-bit value and 512 bits are required
  while(i <= ((nByte * 8 + 159) / 160)):
      hmacsha1 = hmac.new(pmk, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
      R = R + hmacsha1.digest()
      i += 1

  return R[0:nByte]
 
def MakeMIC(ptk, data, wpa = False):
  #Compute the 1st message integrity check for a WPA 4-way handshake
  #ptk:       The Pairwise Transient Key 
  #data:      A list of 802.1x frames with the MIC field zeroed

  #WPA uses md5 to compute the MIC while WPA2 uses sha1
  hmacFunc = md5 if wpa else sha1
  #Create the MICs using HMAC-SHA1 of data and return all computed values
  mic = hmac.new(ptk[0:16], data, hmacFunc).digest()

  return mic[:16]

def valid():
  PMK = b''.fromhex('65 16 4a fd b9 d4 91 8d d5 b6 04 4e 39 eb cb 03 20 da e7 b4 a1 5d cb 8b 31 81 57 d3 dc 94 d9 9e')
  aNonce = b''.fromhex('e8 6a 42 1e af 61 80 f3 d5 ba 98 84 4e 8f 79 51 5b 9f 2d 8c 12 74 fa 7e 1b 40 5b 1a 14 a6 5c 1a')
  sNonce = b''.fromhex('e0 26 45 9c fd af dc 31 c2 db 79 e9 63 85 91 13 71 b3 76 a8 24 57 0a 3a 93 97 b0 2a 00 b3 31 93')
  apMAC = b''.fromhex('64ae0c67b0a2')
  staMAC = b''.fromhex('784f43637912')
  data1 = b''.fromhex('0103007502010a00000000000000000001e026459cfdafdc31c2db79e96385911371b376a824570a3a9397b02a00b33193000000000000000000000000000000000000000000000000000000000000000048571517328121aee5853220d6e2a821001630140100000fac020100000fac040100000fac010000')
  data1_nomic = b''.fromhex('0103007502010a00000000000000000001e026459cfdafdc31c2db79e96385911371b376a824570a3a9397b02a00b33193000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac010000')
  orig_mic1 = b.fromhex('48571517328121aee5853220d6e2a821')

  A,B = MakeAB(aNonce, sNonce, apMAC, staMAC)
  PTK = MakePTK(PMK, A, B)
  mic1 = MakeMIC(PTK, data1_nomic)

  print('PMK: '+PMK.hex())
  print('PTK: '+PTK.hex())
  print('MIC1: '+mic1.hex())
  print('MIC Match: '+str(orig_mic1 == mic1))

def wpenewios():
  b = b''
  PMK = b.fromhex('01 8b de 6d 91 78 ef 44 aa 37 94 ef 2e 73 04 28 6c bd 91 7c c9 22 9a 11 f0 8a 1e f1 59 9f 7c 17')
  aNonce = b.fromhex('d2 7d 00 eb f4 42 f0 a4 d6 d2 83 c5 48 ee 37 bd 9f b5 0b 72 da fe fd 32 93 40 84 c7 fb f8 4e 82')
  sNonce = b.fromhex('d5 28 77 db 86 f4 cf 20 07 f1 00 1d 1b 8d 27 a7 e6 b1 52 34 06 e0 07 a6 de 32 d1 e0 99 f2 b5 2e')
  apMAC = b.fromhex('0a1222334500')
  staMAC = b.fromhex('e0338e223d72')
  data2 = b.fromhex('0203007502010a00100000000000000001d52877db86f4cf2007f1001d1b8d27a7e6b1523406e007a6de32d1e099f2b52e0000000000000000000000000000000000000000000000000000000000000000cdac7a5a0a2fc818d6ff6b2b28edf671001630140100000fac040100000fac040100000fac010c00')
  data2_nomic = b.fromhex('0203007502010a00100000000000000001d52877db86f4cf2007f1001d1b8d27a7e6b1523406e007a6de32d1e099f2b52e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac010c00')
  orig_mic2 = b.fromhex('cdac7a5a0a2fc818d6ff6b2b28edf671')
  data3 = b.fromhex('020300970213ca00100000000000000002d27d00ebf442f0a4d6d283c548ee37bd9fb50b72dafefd32934084c7fbf84e820000000000000000000000000000000000000000000000000000000000000000bdc46f07770f8fde1c11dda7f3000822003837ead57030638f4bb47fbd699e33dcb9a94027fbc879d6d42c91c0bbe6af8d9bdd8fd66844601dfd33383ce9ec0b86c564398fb651493265')
  data3_nomic = b.fromhex('020300970213ca00100000000000000002d27d00ebf442f0a4d6d283c548ee37bd9fb50b72dafefd32934084c7fbf84e82000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003837ead57030638f4bb47fbd699e33dcb9a94027fbc879d6d42c91c0bbe6af8d9bdd8fd66844601dfd33383ce9ec0b86c564398fb651493265')
  orig_mic3 = b.fromhex('bdc46f07770f8fde1c11dda7f3000822')
  A,B = MakeAB(aNonce, sNonce, apMAC, staMAC)
  PTK = MakePTK(PMK, A, B)
  mic2 = MakeMIC(PTK, data2_nomic)
  mic3 = MakeMIC(PTK, data3_nomic)

  print('PMK: '+PMK.hex())
  print('PTK: '+PTK.hex())
  print('mic2: '+mic2.hex())
  print('MIC22 Match: '+str(orig_mic2 == mic2))
  print('mic3: '+mic2.hex())
  print('MIC3 Match: '+str(orig_mic3 == mic3))

embed()
