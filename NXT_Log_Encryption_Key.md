# NXT log file encryption key (logger and decoder)

The Netra X1 logger encrypts every `.NXT` log file as it writes it to the SD card. NXT Netra Pro, the Data Decoder and the Studio decrypt it with the **same key**. The cipher is a symmetric stream cipher: encryption and decryption are the same operation (XOR with a key stream), so there is **one key, not a key pair**.

## The key (16 bytes)

| Form | Value |
|---|---|
| Hex | `3A 7C B5 19 E4 58 C1 0D 92 AF 63 27 FE 34 88 4B` |
| Hex string | `3A7CB519E458C10D92AF6327FE34884B` |
| C / C++ | `{ 0x3A, 0x7C, 0xB5, 0x19, 0xE4, 0x58, 0xC1, 0x0D, 0x92, 0xAF, 0x63, 0x27, 0xFE, 0x34, 0x88, 0x4B }` |
| Python | `[0x3A, 0x7C, 0xB5, 0x19, 0xE4, 0x58, 0xC1, 0x0D, 0x92, 0xAF, 0x63, 0x27, 0xFE, 0x34, 0x88, 0x4B]` |

## Where the key is in the programs

| Program | File | Name in the code |
|---|---|---|
| Logger firmware (encrypts) | `Firmware\Netra_x1_Multiplexer_Version\NXT_Netra_x1_Mux_DL\NXT_Netra_x1_Mux_DL.ino` | `ENCRYPTION_KEY[16]` |
| Data Decoder (decrypts) | `Data_Decoder\Fixed_Data_Decoder.py` | `ENCRYPTION_KEY` |
| NXT Netra Pro (decrypts when it opens or converts a `.NXT` file) | `NXT_Native\suite\src\pro\pro_view.h` (outside OneDrive, build sources) | `V_KEY[16]` |

The three values are identical. If the key is ever changed, it must be changed in the firmware, the decoder, Pro (and the older Studio) together, and files written with the old key can only be read with a program that still has the old key.

## File layout

`.NXT` file = 16-byte header (not encrypted) + the encrypted CSV text.

| Bytes | Content |
|---|---|
| 0 - 5 | signature `NXTLOG` |
| 6 | format version, `1` |
| 7 | reserved |
| 8 - 11 | **nonce**, unsigned 32-bit, little endian: a new random value for every file |
| 12 - 15 | reserved |
| 16 ... | the encrypted data: the CSV header row, then the data rows |

The nonce is not secret. It makes the key stream different in every file.

## The algorithm (encryption and decryption are identical)

Constants: `A = 1664525`, `C = 1013904223`, all arithmetic modulo 2^32.

**Start of the file** (after reading the nonce from the header):

```
state = nonce XOR 0xA5A5A5A5
for each of the 16 key bytes k:
    state = state * A + C + k
```

**For every byte of the data** (the first byte after the header is byte 0):

```
state      = state * A + C
key_byte   = KEY[state & 0x0F]
stream     = ((state >> 24) & 0xFF) XOR key_byte
output     = input XOR stream
```

The decoder's own functions are `init_cipher_state(nonce)` and `cipher_step(state)`; the firmware's are `resetCipherState()` and `encryptByte()`.

## Example: decrypt a file in Python

```python
import struct

KEY = [0x3A, 0x7C, 0xB5, 0x19, 0xE4, 0x58, 0xC1, 0x0D,
       0x92, 0xAF, 0x63, 0x27, 0xFE, 0x34, 0x88, 0x4B]
A, C, M = 1664525, 1013904223, 0xFFFFFFFF

def decrypt_nxt(path_in, path_out):
    with open(path_in, "rb") as f:
        header = f.read(16)
        assert header[:6] == b"NXTLOG" and header[6] == 1
        nonce = struct.unpack("<I", header[8:12])[0]
        state = (nonce ^ 0xA5A5A5A5) & M
        for k in KEY:
            state = (state * A + C + k) & M
        with open(path_out, "wb") as out:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                buf = bytearray(len(chunk))
                for i, b in enumerate(chunk):
                    state = (state * A + C) & M
                    buf[i] = b ^ (((state >> 24) & 0xFF) ^ KEY[state & 0x0F])
                out.write(buf)

# decrypt_nxt("CAN_LOG_20261026_135238.NXT", "CAN_LOG_20261026_135238.csv")
```

(The decoder uses a faster NumPy version of the same calculation. The output is the same.)

## Keep in mind

- This is a **confidentiality hurdle against casual reading of the file, not strong security**: the key is in the firmware image, in the decoder and in Pro, and the cipher is a simple linear generator. Anyone who has the decoder or the firmware file can decrypt the logs. Do not store secrets in the log.
- The key must stay out of anything the customer receives that is not meant to decrypt logs. The customer's copy of Pro and the Decoder can decrypt (that is their job); the source files above are internal.
- Do not confuse this key with the **firmware update keys** (`Software\Tools\secrets\`, used to encrypt and sign `.nxtfw` files) or the **licence signing key**. Those are separate, private, and must never be shared or put in a document like this one.
- The cipher has no integrity check: a damaged or modified file decrypts to garbage in that place, and the decoder reports unreadable rows.
