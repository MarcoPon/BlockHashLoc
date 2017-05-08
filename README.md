# BlockHashLoc


(to be completed...)

tl;dr

 - BHLMake: create a BHL with a list of one hash for every block of a given file
 - BHLReco: scan a disk image/volume for blocks with the hashes from the BHL file to rebuild the original one

With adequately sized blocks (512 bytes, 4KB, etc. depending on the media and file system), this let one recover a file regardless of the FS used, or the FS integrity, or the fragmentation level.

This project is related to [SeqBox](https://github.com/MarcoPon/SeqBox). The differences are:

- SeqBox create a stand-alone file container with the above listed recovery characteristics.
 
- BHL realize the same effect with a parallel (small) file, that can be stored separately (in other media, or in the cloud), or along the original as a SeqBox file (so that it can be recovered too, as the first step).

**N.B.**
Currently the two tools works on one file at the time, but that will obviously change. They are already functional, but it's still a work in progress...

***

## Tech spec

Byte order: Big Endian

Hash: SHA-256

### BHL file structure

| section  | desc                          |
| -------- | ----------------------------- |
| Header   | Signature & version           |
| Metadata | Misc info                     |
| Hash     | Blocks hash list & final hash |


### Header

| pos | to pos | size | desc                              |
|---- | ---    | ---- | --------------------------------- |
|  0  |     12 |  13  | Signature = 'BlockHashLoc' + 0x1a |
| 13  |     13 |   1  | Version byte                      |
| 14  |     16 |   4  | Block size                        |
| 18  |     24 |   8  | File size                         |

### Metadata

| pos | to pos | size | desc                  |
|---- | ------ | ---- | --------------------- |
| 26  |     28 |   4  | Metadata section size |
| 30  |    var |  var | Encoded metadata list |

### Hash

| pos | to pos | size | desc                              |
|---- | ------ | ---- | --------------------------------- |
| var |    var |   32 | 1st block hash                    |
| ... |    ... |   32 | ...                               |
| var |    var |   32 | Last block hash                   |
| var |    var |   32 | Hash of all previous block hashes |


### Versions:

Currently the only version is 1.

### Metadata encoding

| Bytes | Field | 
| ----- | ----- |
|    3  | ID    |
|    1  | Len   |
|    n  | Data  |

#### IDs

| ID | Desc |
| --- | --- |
| FNM | filename (utf-8) |

(others IDs may be added...)


## Links

 - [BlockHashLoc home page](http://mark0.net/)
 - [BlockHashLoc GitHub repository](https://github.com/MarcoPon/BlockHashLoc)

## Credits

The idea of collecting & scanning for block hashes was something I had considered while developing [SeqBox](https://github.com/MarcoPon/SeqBox), then settling on using a stand alone file container instead of the original file plus a parallel one.

Then the concept resurfaced during a nice discussion on Slashdot with user JoeyRoxx, and after some considerations I decided to put some work on that too, seeing how the two approaches could both be useful (in different situations) and even complement each other nicely.

## Contacts

If you need more info, want to get in touch, or donate: [Marco Pontello](http://mark0.net/contacts-e.html)

**Bitcoin**: 1Mark1tF6QGj112F5d3fQALGf41YfzXEK3

![Qr-Code](http://mark0.net/images/qrcode.png) 