# v1t CTF – “Quack” Forensics Challenge Writeup

## Challange name: trynna crack?

Challenge Summary

We are given a password-protected ZIP file. Traditional cracking with john fails.
Inside the ZIP is a corrupted PNG file.
The goal is to extract the real flag.

## 🧩 Step 1 — Known-Plaintext Attack with bkcrack

Since ZIP encryption uses a vulnerable stream cipher, we can use a known plaintext attack on the first PNG bytes.

A PNG file always starts with:
```
89 50 4E 47 0D 0A 1A 0A
00 00 00 0D 49 48 44 52
```

So we create this minimal file:
```
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52' > plain.png

```
Run bkcrack to recover ZIP keys:
```
./bkcrack -C challenge.zip -c quackquackquack.png -p plain.png
```
Recovered keys:
```
4672d551 bcb3adcb c76d52c5

```

Now decrypt the PNG:
```
./bkcrack -C challenge.zip -c quackquackquack.png -k 4672d551 bcb3adcb c76d52c5 -d quack.png
```

## 🧵 Step 2 — Extract Hidden Data from EXIF

Inspect decrypted file:
```
exiftool quack.png
```

We find in the UserComment field:
```
password for zip file =)))) D4mn_br0_H0n3y_p07_7yp3_5h1d
```

This is indeed the ZIP password.

## 🩹 Step 3 — The Original PNG Is Corrupted (Fix IHDR CRC)

The extracted PNG is corrupted due to invalid IHDR CRC.

A small Python script fixes it:
```
import zlib, struct

with open('quackquackquack.png', 'rb') as f:
    data = f.read()

signature = data[:8]
ihdr_length = struct.unpack('>I', data[8:12])[0]
ihdr_type = data[12:16]
ihdr_data = data[16:29]
current_crc = data[29:33]

correct_crc = zlib.crc32(ihdr_type + ihdr_data).to_bytes(4, 'big')

repaired = data[:29] + correct_crc + data[33:]
with open('quack_fixed.png', 'wb') as f:
    f.write(repaired)
```
Opening quack_fixed.png shows:

![fixed image](blog-images/quack_fixed.png)


just kidding the real flag is the password

But using the password directly as v1t{password} still does not work.

## 🏗️ Step 4 — The Image Has More Hidden Content

We inspect further by modifying the height to reveal hidden chunks.

```
with open('quack_fixed.png', 'rb') as f:
    data = bytearray(f.read())

new_height = 1000
data[20:24] = new_height.to_bytes(4, 'big')

import zlib
ihdr_chunk = b'IHDR' + data[16:29]
crc = zlib.crc32(ihdr_chunk).to_bytes(4, 'big')
data[29:33] = crc

with open('quack_tall.png', 'wb') as f:
    f.write(data)
```

Opening quack_tall.png reveals:

![fixed tall image](blog-images/quack_tall.png)

just kidding the real flag is the password in </br>
... .... .- ..... .---- ..---

## 🔍 Step 5 — Decode Morse Code

The morse:
```
... .... .- ..... .---- ..---
```

Translates to:

``SHA512``


So the actual flag is:

SHA-512 hash of the password as the whole thing in the picture makes

just kidding the real flag is the password in SHA512


## 🔐 Step 6 — Compute SHA-512
password:
```
D4mn_br0_H0n3y_p07_7yp3_5h1d
```

Compute SHA-512:
```
echo -n "D4mn_br0_H0n3y_p07_7yp3_5h1d" | sha512sum
```


## 🏁 Final Flag
```
v1t{7083748baa3a42dc0a93811e4f5150e7ae1a050a0929f8c304f707c8c44fc95d86c476d11c9e56709edc30eba5f2d82396f426d93870b56b1a9573eaac8d0373}
```