# understanding-eap
A repository with toy implementations of MSCHAPv2, MPEE and WPA/2 to understand EAP better

Most of the values can be copied from hostapd's debugging output (i.e. run it with -d). By default hostapd will mask these, but if you use hostapd-wpe or hostapd-mana you can see hexdumps of these keys. You could also ask hostapd and wpa_supplicant to use eNULL openssl ciphers and grab them from wireshark, but that's more involved and won't work for "real" supplicants.

For MPEE keys, you'll need to capture traffic between the AP and RADIUS server. If you're using hostapd's built in RADIUS server, you'll need to set up two hostapd's (one as an AP and one as a RADIUS server) so you can capture traffic between them.

# Using MSCHAPv2

The MSCHAPv2 class will perform all the MSCHAPv2 and MPEE crypto calculations.

## Example code

```
from eap import MSCHAPV2
UserName = b'Oliver.Parker'
Password='123456Seven'
AuthenticatorChallenge = b''.fromhex('f5 b8 ad ee e9 ff 08 15 dd 83 e8 2d 89 6e eb 2a')
PeerChallenge = b''.fromhex('e3 32 bf 8e c5 37 e5 72 1d 0d 9a 0e e4 40 46 d6')
KeyLength=128
chap = MSCHAPV2(UserName, Password, AuthenticatorChallenge, PeerChallenge, KeyLength)
chap.Run()
```

## Example output

```
UserName: 4f6c697665722e5061726b6572
Password: 123456Seven
AuthenticatorChallenge: f5b8adeee9ff0815dd83e82d896eeb2a
PeerChallenge: e332bf8ec537e5721d0d9a0ee44046d6
Challenge: ada74b1fca661d15
NTResponse: 6cdadb80dd5310b805f2a0da9bb45ead51ee65344c95e600
PasswordHash: 79337ad5724e777b41e8fc81ad232b6f
PasswordHashHash: 47f66e1914d76e88ba688eb3bd01b51b
MasterKey: e8493e65b13a454b1e0c0c807aa1b723 (EAP-MSCHAPV2: Derived Master Key)
MasterSendKey: cece8ea82527b26c45750608a2c4f6ff
MasterReceiveKey: 67206c73f6797c88d9528a6c6ffed9bc
EAP-MSCHAPV2: Derived key: 67206c73f6797c88d9528a6c6ffed9bccece8ea82527b26c45750608a2c4f6ff
SendSessionKey: 03f403e208c72116870236f08788b8df
ReceiveSessionKey: 79cb2bb67adb4c7cf2f2d4645f54d05a
Send RC4(test messages): ca92e8d42f52d63a042898eb
Receive RC4(test messages): 6fac3674baa72dc327de89ca
```

# Using WPA

The WPA class will perform all the WPA/2 handshake calculations.

## Example code

To check the MIC, you'll need the full bytes of the second handshake frame, with the MIC removed. THat's the difference between data1 and data1_nomic below.

```
from eap import WPA
PMK = b''.fromhex('65 16 4a fd b9 d4 91 8d d5 b6 04 4e 39 eb cb 03 20 da e7 b4 a1 5d cb 8b 31 81 57 d3 dc 94 d9 9e')
aNonce = b''.fromhex('e8 6a 42 1e af 61 80 f3 d5 ba 98 84 4e 8f 79 51 5b 9f 2d 8c 12 74 fa 7e 1b 40 5b 1a 14 a6 5c 1a')
sNonce = b''.fromhex('e0 26 45 9c fd af dc 31 c2 db 79 e9 63 85 91 13 71 b3 76 a8 24 57 0a 3a 93 97 b0 2a 00 b3 31 93')
apMAC = b''.fromhex('64ae0c67b0a2')
staMAC = b''.fromhex('784f43637912')
data1 = b''.fromhex('0103007502010a00000000000000000001e026459cfdafdc31c2db79e96385911371b376a824570a3a9397b02a00b33193000000000000000000000000000000000000000000000000000000000000000048571517328121aee5853220d6e2a821001630140100000fac020100000fac040100000fac010000')
data1_nomic = b''.fromhex('0103007502010a00000000000000000001e026459cfdafdc31c2db79e96385911371b376a824570a3a9397b02a00b33193000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac010000')
wpa = WPA(PMK, aNonce, sNonce, apMAC, staMAC)
wpa.Run(data1_nomic)
```

## Example output

```
PMK: 65164afdb9d4918dd5b6044e39ebcb0320dae7b4a15dcb8b318157d3dc94d99e
PTK: f78161f92716ef5ca3979112d0fd42bcc83da02486c4fcc1e6f13fb8391ba843e4fb1eaeb0160a9896c9d937cadb1066
MIC: 48571517328121aee5853220d6e2a821
```
