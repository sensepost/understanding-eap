#!/usr/bin/env python3

# A Generic MSCHAPv2/MPPE/WPA implementation
# By @singe (research@sensepost.com)
# Used to help understand how PEAP works
# RADIUS server is the Authenticator
# Client is the Station or Peer

from Crypto.Cipher import DES
from Crypto.Cipher import ARC4
from hmac import new as hmac_new
from hashlib import pbkdf2_hmac, sha1, md5, new as hashlib_new

class MSCHAPV2:
  # Generic MSCHAP/MPEE implementation taken from:
  #   https://tools.ietf.org/html/rfc2759#section-8
  #   https://tools.ietf.org/html/rfc3078
  #   https://tools.ietf.org/html/rfc3079

  def __init__(self, UserName, Password, AuthenticatorChallenge, PeerChallenge, KeyLength=128):
    self.UserName = UserName
    self.Password = Password
    self.AuthenticatorChallenge = AuthenticatorChallenge
    self.PeerChallenge = PeerChallenge
    self.KeyLength = KeyLength

  def ChallengeHash(self, PeerChallenge, AuthenticatorChallenge, UserName):
    # Calculate the Challenge both sides(AP + Client) will use
    # This is the challenge part asleap/JtR/hashcat will use to crack

    if len(UserName.split(b'\\')) > 1:
      UserName = UserName.split(b'\\')[1] #Strip DOMAIN\ from front if present

    # Calculate SHA1 hash of Peer+Authenticator+UserName
    sha = sha1()
    sha.update(PeerChallenge)
    sha.update(AuthenticatorChallenge)
    sha.update(UserName)
    Challenge = sha.digest()

    # Return first 8 bytes of challenge as hex
    Challenge = Challenge[0:8]
    return Challenge

  def NtPasswordHash(self, Password):
    # MD4 the password with right encoding
    Password = Password.encode('utf-16le')

    md4 = hashlib_new('md4')
    md4.update(Password)
    PasswordHash = md4.digest()

    return PasswordHash

  def HashNtPasswordHash(self, PasswordHash):
    # Generate the double hash'ed Hash
    md4 = hashlib_new('md4')
    md4.update(PasswordHash)
    PasswordHashHash = md4.digest()

    return PasswordHashHash

  # Copied from https://github.com/SecureAuthCorp/impacket/blob/1c21a460ae1f8d20e7c35c2d4b123800472feeb3/impacket/ntlm.py#L534
  def __expand_DES_key(self, key):
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

  def ChallengeResponse(self, Challenge, PasswordHash):
    # Generate the NTResponse the client sends the AP
    # This is the response part asleap/JtR/hashcat crack

    ZPasswordHash = PasswordHash+b'\x00\x00\x00\x00\x00'

    des = DES.new(self.__expand_DES_key(ZPasswordHash[0:7]),DES.MODE_ECB)
    one = des.encrypt(Challenge)
    des = DES.new(self.__expand_DES_key(ZPasswordHash[7:14]),DES.MODE_ECB)
    two = des.encrypt(Challenge)
    des = DES.new(self.__expand_DES_key(ZPasswordHash[14:21]),DES.MODE_ECB)
    tre = des.encrypt(Challenge)

    Response = one+two+tre

    return Response

  def GenerateAuthenticatorResponse(self, Password, NTResponse, PeerChallenge, AuthenticatorChallenge, UserName):
    # Create the response the AP sends to the Client to prove it knows the password too

    # Defined in https://tools.ietf.org/html/rfc2759#section-8
    Magic1 = b'\x4D\x61\x67\x69\x63\x20\x73\x65\x72\x76\x65\x72\x20\x74\x6F\x20\x63\x6C\x69\x65\x6E\x74\x20\x73\x69\x67\x6E\x69\x6E\x67\x20\x63\x6F\x6E\x73\x74\x61\x6E\x74' #39 bytes
    Magic2 = b'\x50\x61\x64\x20\x74\x6F\x20\x6D\x61\x6B\x65\x20\x69\x74\x20\x64\x6F\x20\x6D\x6F\x72\x65\x20\x74\x68\x61\x6E\x20\x6F\x6E\x65\x20\x69\x74\x65\x72\x61\x74\x69\x6F\x6E' #41 bytes

    PasswordHash = self.NtPasswordHash(Password)
    PasswordHashHash = self.HashNtPasswordHash(PasswordHash)

    Challenge = self.ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName)

    sha = sha1()
    sha.update(PasswordHashHash)
    sha.update(NTResponse)
    sha.update(Magic1)
    Digest = sha.digest()

    sha = sha1()
    sha.update(Digest)
    sha.update(Challenge)
    sha.update(Magic2)
    AuthenticatorResponse = sha.digest()
    AuthenticatorResponse = "S="+AuthenticatorResponse.hex().upper()

    return AuthenticatorResponse

  def GetMasterKey(self, PasswordHashHash, NTResponse):
    # Generate Master Key used to derive PMK part of MPPE not MSCHAP
    # https://tools.ietf.org/html/rfc3079#section-3.4

    # Taken from RFC 3079
    Magic1 = b'\x54\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x4d\x50\x50\x45\x20\x4d\x61\x73\x74\x65\x72\x20\x4b\x65\x79' #27 bytes

    sha = sha1()
    sha.update(PasswordHashHash)
    sha.update(NTResponse)
    sha.update(Magic1)
    MasterKey = sha.digest()

    return MasterKey[:16]

  def GetAsymetricStartKey(self, MasterKey, SessionKeyLength, IsSend, IsServer):
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
      
    sha = sha1()
    sha.update(MasterKey)
    sha.update(SHSpad1)
    sha.update(s)
    sha.update(SHSpad2)
    SessionKey = sha.digest()

    return SessionKey[:SessionKeyLength]

  def GetNewKeyFromSHA(self, StartKey, SessionKey, SessionKeyLength):
    # Generate the initial send session key MPEE
    # https://tools.ietf.org/html/rfc3078 Section 7.3

    SHApad1 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #40 Bytes
    SHApad2 = b'\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2\xf2' #40 Bytes

    sha = sha1()
    sha.update(StartKey[:SessionKeyLength])
    sha.update(SHApad1)
    sha.update(SessionKey[:SessionKeyLength])
    sha.update(SHApad2)
    InterimKey = sha.digest()

    return InterimKey[:SessionKeyLength]

  def ReduceSessionKey(self, SendSessionKey, KeyLength):
    # Reduce key size appropriately
    # https://tools.ietf.org/html/rfc3079#section-3.1 3.2 & 3.3
    if KeyLength == 40:
      return b'\xd1\x26\x9e'+SendSessionKey[3:]
    if KeyLength == 56:
      return b'\xd1'+SendSessionKey[1:]
    if KeyLength == 128 or KeyLength == 256:
      return SendSessionKey

  def rc4_key(self, SessionKey):
    # Initialise RC4 tables with Session key
    # https://tools.ietf.org/html/rfc3079#section-3.3

    rc4 = ARC4.new(SessionKey)
    return rc4

  def Run(self):
    PasswordHash = self.NtPasswordHash(self.Password)
    PasswordHashHash = self.HashNtPasswordHash(PasswordHash)
    Challenge = self.ChallengeHash(self.PeerChallenge, self.AuthenticatorChallenge, self.UserName)
    NTResponse = self.ChallengeResponse(Challenge, PasswordHash)
    MasterKey = self.GetMasterKey(PasswordHashHash, NTResponse)
    AuthenticatorResponse = self.GenerateAuthenticatorResponse(self.Password, NTResponse, self.PeerChallenge, self.AuthenticatorChallenge, self.UserName)

    if self.KeyLength == 40 or self.KeyLength == 56:
      length = 8
    elif self.KeyLength == 128:
      length = 16
    elif self.KeyLength == 256:
      length = 32

    MasterSendKey = self.GetAsymetricStartKey(MasterKey, length, True, True)
    MasterReceiveKey = self.GetAsymetricStartKey(MasterKey, length, False, True)
    SendSessionKey = self.GetNewKeyFromSHA(MasterSendKey, MasterSendKey, length)
    ReceiveSessionKey = self.GetNewKeyFromSHA(MasterReceiveKey, MasterReceiveKey, length)
    SendSessionKey = self.ReduceSessionKey(SendSessionKey, self.KeyLength)
    ReceiveSessionKey = self.ReduceSessionKey(ReceiveSessionKey, self.KeyLength)
    SendRC4 = self.rc4_key(SendSessionKey)
    ReceiveRC4 = self.rc4_key(ReceiveSessionKey)

    print('UserName: '+self.UserName.hex()) 
    print('Password: '+self.Password) 
    print('AuthenticatorChallenge: '+self.AuthenticatorChallenge.hex()) 
    print('PeerChallenge: '+self.PeerChallenge.hex()) 
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

    self.Challenge = Challenge
    self.NTResponse = NTResponse
    self.AuthenticatorResponse = AuthenticatorResponse
    self.PasswordHash = PasswordHash
    self.PasswordHashHash = PasswordHashHash
    self.MasterKey = MasterKey
    self.MasterSendKey = MasterSendKey
    self.MasterReceiveKey = MasterReceiveKey
    self.SendSessionKey = SendSessionKey
    self.ReceiveSessionKey = ReceiveSessionKey
    self.SendRC4 = SendRC4
    self.ReceiveRC4 = ReceiveRC4

    return self.Challenge, self.NTResponse, self.AuthenticatorResponse, self.PasswordHash, self.PasswordHashHash, self.MasterKey, self.MasterSendKey, self.MasterReceiveKey, self.SendSessionKey, self.ReceiveSessionKey, self.SendRC4, self.ReceiveRC4

class WPA:
  # Generic WPA/2 implementation
  # Original source https://nicholastsmith.wordpress.com/2016/11/15/wpa2-key-derivation-with-anaconda-python/

  def __init__(self, password, ssid, aNonce, sNonce, apMac, staMac):
    self.password = password
    self.ssid = ssid
    self.aNonce = aNonce
    self.sNonce = sNonce
    self.apMac = apMac
    self.staMac = staMac

  def __init__(self, PMK, aNonce, sNonce, apMac, staMac):
    self.pmk = PMK
    self.aNonce = aNonce
    self.sNonce = sNonce
    self.apMac = apMac
    self.staMac = staMac

  def MakePMK(self, pwd, ssid):
    #Create the pairwise master key using 4096 iterations of hmac-sha1
    #to generate a 32 byte value
    pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)

    return pmk

  def MakeAB(self, aNonce, sNonce, apMac, staMac):
    #Make parameters for the generation of the PTK
    #aNonce:        The aNonce from the 4-way handshake
    #sNonce:        The sNonce from the 4-way handshake
    #apMac:         The MAC address of the access point
    #staMac:        The MAC address of the client
    #return:        (A, B) where A and B are parameters for the generation of the PTK

    A = b"Pairwise key expansion"
    B = min(apMac, staMac) + max(apMac, staMac) + min(aNonce, sNonce) + max(aNonce, sNonce)

    return (A, B)
   
  def MakePTK(self, pmk, A, B):
    #Pseudo-random function for generation of
    #the pairwise transient key (PTK)
    #key:       The PMK
    #A:         b'Pairwise key expansion'
    #B:         The apMac, staMac, aNonce, and sNonce concatenated
    #           like mac1 mac2 nonce1 nonce2
    #           such that mac1 < mac2 and nonce1 < nonce2
    #return:    The ptk

    #Number of bytes in the PTK
    nByte = 48
    i = 0
    R = b''
    #Each iteration produces 160-bit value and 512 bits are required
    while(i <= ((nByte * 8 + 159) / 160)):
        hmacsha1 = hmac_new(pmk, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        i += 1

    return R[0:nByte]
   
  def MakeMIC(self, ptk, data, wpa = False):
    #Compute the 1st message integrity check for a WPA 4-way handshake
    #ptk:       The Pairwise Transient Key 
    #data:      A list of 802.1x frames with the MIC field zeroed

    #WPA uses md5 to compute the MIC while WPA2 uses sha1
    hmacFunc = md5 if wpa else sha1
    #Create the MICs using HMAC-SHA1 of data and return all computed values
    mic = hmac_new(ptk[0:16], data, hmacFunc).digest()

    return mic[:16]

  def Run(self, data, wpa = False):
    A,B = self.MakeAB(self.aNonce, self.sNonce, self.apMac, self.staMac)
    if hasattr(self, 'password'):
      PMK = self.MakePMK(self.password, self.ssid)
    else:
      PMK = self.pmk
    PTK = self.MakePTK(PMK, A, B)
    MIC = self.MakeMIC(PTK, data, wpa)

    print('PMK: '+PMK.hex())
    print('PTK: '+PTK.hex())
    print('MIC: '+MIC.hex())

    self.A = A
    self.B = B
    self.PMK = PMK
    self.PTK = PTK
    self.MIC = MIC

    return A, B, PMK, PTK, MIC
