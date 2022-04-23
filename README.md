# ST25TA NFC tag reader
Just a small piece of code to access [NFC STM ST25TA tags](https://www.st.com/en/nfc/st25ta-series-nfc-tags.html) and read their content. Not really a tool yet but a simple PoC using [libNFC](https://github.com/nfc-tools/libnfc) to manipulate ST25TA tags with a libNFC compatible reader (ACR122, SCL3711, LoGO ASK, etc).

Currently implemented features:
- get tag information
- read tag content
- select the file to read
- verbose mode showing ADPUs
- authenticate against the tag before reading (password protected tags)
- supports tags configured with multiple files

Example of use:

```
$ ./st25taread -h
ST25TA reader v0.0.1
Copyright (c) 2022 - Denis Bodor

Usage : ./st25taread [OPTIONS]
 -i              get info on tag
 -r              read data from tag
 -p password     use this read password (space allowed)
 -f n            use nth file from CC when reading (default: use first file)
 -l              list available readers
 -d connstring   use this device (default: use the first available device)
 -v              verbose mode
 -h              show this help

$ ./st25taread -i
NFC reader: ASK / LoGO opened
ISO/IEC 14443A (106 kbps) tag found. UID: 02C4004E3771A4

ST System file
  Len:                      18
  UID:                      02C4004E3771A4
  Memory Size (-1):         8191
  Product:                  ST25TA64K (0xC4)
  Number of NDEF file:      1

Capability Container file
  Len:                      15
  Version:                  v2.0
  MLe max R-APDU data size: 246
  MLc max C-APDU data size: 246
  NDEF file control TLV (Tag/Length/Value):
    file id:                0001
    type of file:           NDEF (04)
    max ndef size:          8192
    read access:            00 (Unlocked)
    write access:           00 (Unlocked)

$ ./st25taread -r
NFC reader: ASK / LoGO opened
ISO/IEC 14443A (106 kbps) tag found. UID: 02C4004E447224

NDEF data (47):
d1 01 2b 54 02 66 72 43 6f 75 63 6f 75 20 63 65
63 69 20 65 73 74 20 75 6e 20 74 65 78 74 65 20
6a 75 73 74 65 20 70 6f 75 72 20 76 6f 69 72

$ ./st25taread -vr
NFC reader: ASK / LoGO opened
ISO/IEC 14443A (106 kbps) tag found. UID: 02C4004E447224
=> 00 a4 04 00 07 d2 76 00 00 85 01 01 00
<= 90 00
=> 00 a4 00 0c 02 e1 03
<= 90 00
=> 00 b0 00 00 02
<= 00 0f 90 00
=> 00 b0 00 00 0f
<= 00 0f 20 00 f6 00 f6 04 06 00 01 20 00 00 00 90 00
=> 00 a4 00 0c 02 00 01
<= 90 00
=> 00 b0 00 00 02
<= 00 2f 90 00
=> 00 b0 00 02 2f
<= d1 01 2b 54 02 66 72 43 6f 75 63 6f 75 20 63 65 63 69 20 65 73 74 20 75 6e 20 74 65 78 74 65 20 6a 75 73 74 65 20 70 6f 75 72 20 76 6f 69 72 90 00

NDEF data (47):
d1 01 2b 54 02 66 72 43 6f 75 63 6f 75 20 63 65
63 69 20 65 73 74 20 75 6e 20 74 65 78 74 65 20
6a 75 73 74 65 20 70 6f 75 72 20 76 6f 69 72
```

