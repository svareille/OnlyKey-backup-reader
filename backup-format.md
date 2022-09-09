# OnlyKey Backup

## Format of the backup

```
-----BEGIN ONLYKEY BACKUP-----
<base64-encoded OnlyKey content>
--<base64-encoded SHA256 sum>
-----END ONLYKEY BACKUP-----
```

The SHA256 is done on the raw OnlyKey content (before base64 encoding).

## Encryption/Decryption algorithm

### Passphrase

Encryption and decryption with the passphrase is essentially the same as with an ECC key :

1. The passphrase is SHA256 hashed, producing a 32 byte value.
2. This value is used as a private ECC key.
3. Follow the ECC algorithm described below.

### ECC

ECC decryption is as follow (pseudo-code):

```
shared_secret: [byte; 32] = crypto_box_beforenm(public_key, private_key)
iv: [byte; 12] = <last 12 bytes of raw backup (after base64 decoding)>
aes_key: [byte; 32] = SHA256(shared_secret).update(public_key).update(iv)
decrypted = Aes256Gcm_decrypt(encrypted, aes_key, iv)
return decrypted
```

With `crypto_box_beforenm` as defined by [NaCl](https://nacl.cr.yp.to/box.html). This is essentially
a combination of X25519 and XSalsa20Poly1305. The result of the
[x25519 function](https://www.rfc-editor.org/rfc/rfc7748) (which takes the private key and the public
key) is given to the `key` parameter of the 
[HSalsa20 function](https://cr.yp.to/snuffle/xsalsa-20110204.pdf), with an empty `input`.

### RSA

RSA encryption is as follow (pseudo-code):

```
iv: [byte, 12] = "BACKUP12345" // There is a final NULL character at the end
aes_key: [byte, 32] = randbytes(32)
encrypted = AES256GCM_encrypt(raw, aes_key, iv)
encrypted_key: [byte, 32] = RSA_encrypt(aes_key)
return encrypted + encrypted_key
```

## OnlyKey content
The decoded content is :

#### Label
```
| 1B |     1B      | 1B |  16B  |
 0xFF <slot number> 0x01 <label>
```
Total: 19 bytes.

#### Url
```
| 1B |     1B      | 1B | 0-56B |
 0xFF <slot number> 0x0F  <url>
```
Total: 3-59 bytes.

#### Username
```
| 1B |     1B      | 1B |  0-56B   |
 0xFF <slot number> 0x02 <username>
```
Total: 3-59 bytes.

#### Password
```
| 1B |     1B      | 1B |  0-56B   |
 0xFF <slot number> 0x05 <password>
```
Total: 3-59 bytes.

#### Character after username
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x10 <value>
```
Total: 4 bytes.

With `value`:
	0: None
	1: Tab
	2: Return

#### Character after password
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x03 <value>
```
Total: 4 bytes.

With `value`:
	0: None
	1: Tab
	2: Return

#### Return after OTP
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x06 <value>
```
Total: 4 bytes.

With `value`:
	Unknown

#### Tab before username
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x12 <value>
```
Total: 4 bytes.

With `value`:
	0: No
	1: Yes

#### Tab before OTP
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x13 <value>
```
Total: 4 bytes.

With `value`:
	0: No
	1: Yes

#### Delay before username
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x11 <delay>
```
Total: 4 bytes.

With `delay` in [0; 10]

#### Delay before password
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x04 <delay>
```
Total: 4 bytes.

With `delay` in [0; 10]

#### Delay before OTP
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x07 <delay>
```
Total: 4 bytes.

With `delay` in [0; 10]

#### Typing speed
```
| 1B |     1B      | 1B |  1B   |
 0xFF <slot number> 0x0D <speed>
```
Total: 4 bytes.

With `speed` in [1; 10]

#### 2FA type
```
| 1B |     1B      | 1B |  1B  |
 0xFF <slot number> 0x08 <type>
```
Total: 4 bytes.

With `type`:
	0: None
	50: YubiOTP and HMAC SHA1
	72: HMAC SHA1
	89: YubiOTP
	103: GoogleAuth (TOTP)
	117: Old U2F
	121: Old YubiOTP

#### 2FA values
```
| 1B |     1B      | 1B |   1B   | length |
 0xFF <slot number> 0x09 <length>   <2FA>
```
Total: 4+`length` bytes

#### Authentication state (fido)
```
| 1B | 1B |       1B       |     1B     |      32B      |    32B   |  2B  |    4B    |
 0xFE 0x00 <is_initialized> <is_pin_set> <PIN_CODE_HASH> <PIN_SALT> 0xFFFF <reserved>
|       1B       | 1B |     2B    |    2B    |    128B   |      1B      | 1B |
<remaining_tries> 0xFF <rk_stored> <key_lens> <key_space> <data_version> 0xFF
```
Total: 210 bytes

#### Resident key
```
| 1B |   1B  |                 | 16B |   18B   |    32B   |   4B  |
 0xFE <index> [CredentialID id] <tag> <entropy> <rpIdHash> <count>
|                     | 64B |    1B   |  65B |     64B     | 128B |
[CTAP_userEntity user]| <id> <id_size> <name> <displayName> <icon>
|  48B |    1B    |
 <rpId> <rpIdSize>
```
Total: 443 bytes

With `index` the index of the resident key + 200 (200, 201, 202...)

