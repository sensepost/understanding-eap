#!/usr/bin/env python3

# A Generic MSCHAPv2/MPPE implementation
# By @singe (research@sensepost.com)
# Used to help understand how PEAP works
# Taken from:
#   https://tools.ietf.org/html/rfc2759#section-8
#   https://tools.ietf.org/html/rfc3078
#   https://tools.ietf.org/html/rfc3079
# RADIUS server is the Authenticator
# Client is the Station or Peer

import hashlib
from Crypto.Cipher import DES
from Crypto.Cipher import ARC4
from IPython import embed

def ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName):
  # Calculate the Challenge both sides(AP + Client) will use
  # This is the challenge part asleap/JtR/hashcat will use to crack

  if len(UserName.split(b'\\')) > 1:
    UserName = UserName.split(b'\\')[1] #Strip DOMAIN\ from front if present

  # Calculate SHA1 hash of Peer+Authenticator+UserName
  sha1 = hashlib.sha1()
  sha1.update(PeerChallenge)
  sha1.update(AuthenticatorChallenge)
  sha1.update(UserName)
  Challenge = sha1.digest()

  # Return first 8 bytes of challenge as hex
  Challenge = Challenge[0:8]
  return Challenge

def NtPasswordHash(Password):
  # MD4 the password with right encoding
  Password = Password.encode('utf-16le')

  md4 = hashlib.new('md4')
  md4.update(Password)
  PasswordHash = md4.digest()

  return PasswordHash

def HashNtPasswordHash(PasswordHash):
  # Generate the double hash'ed Hash
  md4 = hashlib.new('md4')
  md4.update(PasswordHash)
  PasswordHashHash = md4.digest()

  return PasswordHashHash

# Copied from https://github.com/SecureAuthCorp/impacket/blob/1c21a460ae1f8d20e7c35c2d4b123800472feeb3/impacket/ntlm.py#L534
def __expand_DES_key(key):
  # Expand the key from a 7-byte password key into a 8-byte DES key
  key  = key[:7]
  key += bytearray(7-len(key))
  s = bytearray()
  s.append(((key[0] >> 1) & 0x7f) << 1)
  s.append(((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1)
  s.append(((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1)
  s.append(((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1)
  s.append(((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1)
  s.append(((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1)
  s.append(((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1)
  s.append((key[6] & 0x7f) << 1)
  return bytes(s)

def ChallengeResponse(Challenge, PasswordHash):
  # Generate the NTResponse the client sends the AP
  # This is the response part asleap/JtR/hashcat crack

  ZPasswordHash = PasswordHash+b'\x00\x00\x00\x00\x00'

  des = DES.new(__expand_DES_key(ZPasswordHash[0:7]),DES.MODE_ECB)
  one = des.encrypt(Challenge)
  des = DES.new(__expand_DES_key(ZPasswordHash[7:14]),DES.MODE_ECB)
  two = des.encrypt(Challenge)
  des = DES.new(__expand_DES_key(ZPasswordHash[14:21]),DES.MODE_ECB)
  tre = des.encrypt(Challenge)

  Response = one+two+tre

  return Response

def GenerateAuthenticatorResponse(Password, NTResponse, PeerChallenge, AuthenticatorChallenge, UserName):
  # Create the response the AP sends to the Client to prove it knows the password too

  # Defined in https://tools.ietf.org/html/rfc2759#section-8
  Magic1 = b'\x4D\x61\x67\x69\x63\x20\x73\x65\x72\x76\x65\x72\x20\x74\x6F\x20\x63\x6C\x69\x65\x6E\x74\x20\x73\x69\x67\x6E\x69\x6E\x67\x20\x63\x6F\x6E\x73\x74\x61\x6E\x74' #39 bytes
  Magic2 = b'\x50\x61\x64\x20\x74\x6F\x20\x6D\x61\x6B\x65\x20\x69\x74\x20\x64\x6F\x20\x6D\x6F\x72\x65\x20\x74\x68\x61\x6E\x20\x6F\x6E\x65\x20\x69\x74\x65\x72\x61\x74\x69\x6F\x6E' #41 bytes

  PasswordHash = NtPasswordHash(Password)
  PasswordHashHash = HashNtPasswordHash(PasswordHash)

  Challenge = ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName)

  sha1 = hashlib.sha1()
  sha1.update(PasswordHashHash)
  sha1.update(NTResponse)
  sha1.update(Magic1)
  Digest = sha1.digest()

  sha1 = hashlib.sha1()
  sha1.update(Digest)
  sha1.update(Challenge)
  sha1.update(Magic2)
  AuthenticatorResponse = sha1.digest()
  AuthenticatorResponse = "S="+AuthenticatorResponse.hex().upper()

  return AuthenticatorResponse

def GetMasterKey(PasswordHashHash, NTResponse):
  # Generate Master Key used to derive PMK part of MPPE not MSCHAP
  # https://tools.ietf.org/html/rfc3079#section-3.4

  # Taken from RFC 3079
  Magic1 = b'\x54\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x4d\x50\x50\x45\x20\x4d\x61\x73\x74\x65\x72\x20\x4b\x65\x79' #27 bytes

  sha1 = hashlib.sha1()
  sha1.update(PasswordHashHash)
  sha1.update(NTResponse)
  sha1.update(Magic1)
  MasterKey = sha1.digest()

  return MasterKey[:16]

def GetAsymetricStartKey(MasterKey, SessionKeyLength, IsSend, IsServer):
  # Generate MS-MPEE-Send/Recv-Key
  # From https://tools.ietf.org/html/rfc3079#section-3.4
  # IsSend & IsServer == True - master send session key

  Magic2 = b'\x4f\x6e\x20\x74\x68\x65\x20\x63\x6c\x69\x65\x6e\x74\x20\x73\x69\x64\x65\x2c\x20\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x73\x65\x6e\x64\x20\x6b\x65\x79\x3b\x20\x6f\x6e\x20\x74\x68\x65\x20\x73\x65\x72\x76\x65\x72\x20\x73\x69\x64\x65\x2c\x20\x69\x74\x20\x69\x73\x20\x74\x68\x65\x20\x72\x65\x63\x65\x69\x76\x65\x20\x6b\x65\x79\x2e' #84 Bytes
  Magic3 = b'\x4f\x6e\x20\x74\x68\x65\x20\x63\x6c\x69\x65\x6e\x74\x20\x73\x69\x64\x65\x2c\x20\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x72\x65\x63\x65\x69\x76\x65\x20\x6b\x65\x79\x3b\x20\x6f\x6e\x20\x74\x68\x65\x20\x73\x65\x72\x76\x65\x72\x20\x73\x69\x64\x65\x2c\x20\x69\x74\x20\x69\x73\x20\x74\x68\x65\x20\x73\x65\x6e\x64\x20\x6b\x65\x79\x2e' #84 Bytes
  SHSpad1 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #40 Bytes
  SHSpad2 = b'\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2' #40 Bytes
  
  if IsSend:
    if IsServer:
      s = Magic3
    else:
      s = Magic2
  else:
    if IsServer:
      s = Magic2
    else:
      s = Magic3
    
  sha1 = hashlib.sha1()
  sha1.update(MasterKey)
  sha1.update(SHSpad1)
  sha1.update(s)
  sha1.update(SHSpad2)
  SessionKey = sha1.digest()

  return SessionKey[:SessionKeyLength]

def GetNewKeyFromSHA(StartKey, SessionKey, SessionKeyLength):
  # Generate the initial send session key MPEE
  # https://tools.ietf.org/html/rfc3078 Section 7.3

  SHApad1 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #40 Bytes
  SHApad2 = b'\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2' #40 Bytes

  sha1 = hashlib.sha1()
  sha1.update(StartKey[:SessionKeyLength])
  sha1.update(SHApad1)
  sha1.update(SessionKey[:SessionKeyLength])
  sha1.update(SHApad2)
  InterimKey = sha1.digest()

  return InterimKey[:SessionKeyLength]

def ReduceSessionKey(SendSessionKey, KeyLength):
  # Reduce key size appropriately
  # https://tools.ietf.org/html/rfc3079#section-3.1 3.2 & 3.3
  if KeyLength == 40:
    return b'\xd1\x26\x9e'+SendSessionKey[3:]
  if KeyLength == 56:
    return b'\xd1'+SendSessionKey[1:]
  if KeyLength == 128 or KeyLength == 256:
    return SendSessionKey

def rc4_key(SessionKey):
  # Initialise RC4 tables with Session key
  # https://tools.ietf.org/html/rfc3079#section-3.3

  rc4 = ARC4.new(SessionKey)
  return rc4

def AllTogetherNow(UserName, Password, AuthenticatorChallenge, PeerChallenge, KeyLength):
  PasswordHash = NtPasswordHash(Password)
  PasswordHashHash = HashNtPasswordHash(PasswordHash)
  Challenge = ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName)
  NTResponse = ChallengeResponse(Challenge,PasswordHash)
  MasterKey = GetMasterKey(PasswordHashHash, NTResponse)

  if KeyLength == 40 or KeyLength == 56:
    length = 8
  elif KeyLength == 128:
    length = 16
  elif KeyLength == 256:
    length = 32

  MasterSendKey = GetAsymetricStartKey(MasterKey, length, True, True)
  MasterReceiveKey = GetAsymetricStartKey(MasterKey, length, False, True)
  SendSessionKey = GetNewKeyFromSHA(MasterSendKey, MasterSendKey, length)
  ReceiveSessionKey = GetNewKeyFromSHA(MasterReceiveKey, MasterReceiveKey, length)
  SendSessionKey = ReduceSessionKey(SendSessionKey, KeyLength)
  ReceiveSessionKey = ReduceSessionKey(ReceiveSessionKey, KeyLength)
  SendRC4 = rc4_key(SendSessionKey)
  ReceiveRC4 = rc4_key(ReceiveSessionKey)

  print('UserName: '+UserName.hex()) 
  print('Password: '+Password) 
  print('AuthenticatorChallenge: '+AuthenticatorChallenge.hex()) 
  print('PeerChallenge: '+PeerChallenge.hex()) 
  print('Challenge: '+Challenge.hex()) 
  print('NTResponse: '+NTResponse.hex()) 
  print('PasswordHash: '+PasswordHash.hex()) 
  print('PasswordHashHash: '+PasswordHashHash.hex()) 
  print('MasterKey: '+MasterKey.hex()+' (EAP-MSCHAPV2: Derived Master Key)')
  print('MasterSendKey: '+MasterSendKey.hex()) 
  print('MasterReceiveKey: '+MasterReceiveKey.hex()) 
  print('EAP-MSCHAPV2: Derived key: '+MasterReceiveKey.hex()+MasterSendKey.hex())
  print('SendSessionKey: '+SendSessionKey.hex()) 
  print('ReceiveSessionKey: '+ReceiveSessionKey.hex()) 
  print('Send RC4(test messages): '+SendRC4.encrypt('test message').hex()) 
  print('Receive RC4(test messages): '+ReceiveRC4.encrypt('test message').hex()) 
  return Challenge, NTResponse, PasswordHash, PasswordHashHash, MasterKey, MasterSendKey, MasterReceiveKey, SendSessionKey, ReceiveSessionKey, SendRC4, ReceiveRC4

b=b''
UserName = b.fromhex('55 73 65 72')
Password = b.fromhex('63 00 6C 00 69 00 65 00 6E 00 74 00 50 00 61 00 73 00 73 00')
Password = 'clientPass'
AuthenticatorChallenge = b.fromhex('5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28')
PeerChallenge = b.fromhex('21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E')

KeyLength=40
Challenge, NTResponse, PasswordHash, PasswordHashHash, MasterKey, MasterSendKey, MasterReceiveKey, SendSessionKey, ReceiveSessionKey, SendRC4, ReceiveRC4 = AllTogetherNow(UserName, Password, AuthenticatorChallenge, PeerChallenge, KeyLength)
KeyLength=56
Challenge, NTResponse, PasswordHash, PasswordHashHash, MasterKey, MasterSendKey, MasterReceiveKey, SendSessionKey, ReceiveSessionKey, SendRC4, ReceiveRC4 = AllTogetherNow(UserName, Password, AuthenticatorChallenge, PeerChallenge, KeyLength)
KeyLength=128
Challenge, NTResponse, PasswordHash, PasswordHashHash, MasterKey, MasterSendKey, MasterReceiveKey, SendSessionKey, ReceiveSessionKey, SendRC4, ReceiveRC4 = AllTogetherNow(UserName, Password, AuthenticatorChallenge, PeerChallenge, KeyLength)

embed()

