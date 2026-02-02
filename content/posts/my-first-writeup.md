---
title: "My First CTF Writeup - Sample Challenge"
description: "A sample CTF writeup showcasing crypto challenge from SNICTF 2025"
date: 2026-01-28
draft: false
image: ""
categories:
  - Write-Up
tags:
  - National
  - SNICTF
  - Individual
  - LastSeenIn2026
---

## Challenge Description

This was an interesting cryptography challenge from SNICTF 2025. The challenge provided us with an encrypted message and a hint about the cipher used.

**Challenge Name:** SecretMessage  
**Category:** Cryptography  
**Points:** 100  
**Difficulty:** Medium

We were given the following encrypted text:

```
Uryyb Jbeyq! Guvf vf n frperg zrffntr.
```

And a hint: "Julius would be proud"

## Solution

Based on the hint mentioning Julius (Julius Caesar), I immediately recognized this as a Caesar cipher. The Caesar cipher is a simple substitution cipher where each letter is shifted by a fixed number of positions in the alphabet.

### Step 1: Identify the Cipher

Looking at the pattern and the hint, it's clearly a ROT13 cipher (a Caesar cipher with shift of 13).

### Step 2: Decryption

I used CyberChef to decode the message. Here's a Python script that can also decode it:

```python
def rot13(text):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += char
    return result

encrypted = "Uryyb Jbeyq! Guvf vf n frperg zrffntr."
decrypted = rot13(encrypted)
print(decrypted)
```

Running this gives us:

```
Hello World! This is a secret message.
```

### Step 3: Finding the Flag

After decrypting the message, I explored the challenge server more carefully. There was a hidden endpoint that required authentication with the decoded message. Accessing it revealed the flag.

## Flag

```
flag{r0t13_1s_n0t_s3cur3_encryption}
```

## Key Takeaways

- Always pay attention to hints in CTF challenges
- ROT13 is a classic cipher that appears frequently in beginner CTF challenges
- CyberChef is an excellent tool for quick cryptography operations
- Sometimes the solution requires multiple steps beyond just decoding

## Tools Used

- [CyberChef](https://gchq.github.io/CyberChef/)
- Python 3
- Custom Python script for ROT13 decoding
