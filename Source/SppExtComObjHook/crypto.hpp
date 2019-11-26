#pragma once

// KMS V4 Rijndael-160 CMAC
void GetV4Cmac(int MessageSize, const BYTE *Message, BYTE *HashOut);

// KMS V5/V6 AES-128 CBC encryption
BOOL AesEncryptMessage(DWORD Version, const BYTE *IV, BYTE *Message, DWORD *MessageSize, DWORD MessageBufLen);

// KMS V5/V6 AES-128 CBC decryption
BOOL AesDecryptMessage(DWORD Version, const BYTE *IV, BYTE *Message, DWORD *MessageSize);

// KMS V5/V6 SHA-256 hash
BOOL GetSha256Hash(const BYTE *data, DWORD dataSize, BYTE *Hash);

// KMS V6 HMAC-SHA256 key
void GetHmacKey(const ULONG64 *TimeStamp, BYTE *Key);

// KMS V6 HMAC-SHA256
BOOL GetHmacSha256(const BYTE *pbKey, DWORD dwDataLen, const BYTE *pbData, BYTE *pbHash);

// PRNG using Win32 Crypto API provider
BOOL GetRandomBytes(BYTE *RandomBuffer, DWORD RandomBufferLength);

// Xor 16-bytes source into destination
void XorBuffer(const BYTE *source, BYTE *destination);
