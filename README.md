# BlockHashLoc

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
|  0  |     11 |  12  | Signature = 'BlockHashLoc' + 0x1a |
| 12  |     12 |   1  | Version byte                      |
| 13  |     16 |   4  | Block size                        |
| 17  |     24 |   8  | File size                         |

### Metadata

| pos | to pos | size | desc                  |
|---- | ------ | ---- | --------------------- |
| 25  |     28 |   4  | Metadata section size |
| 29  |    var |  var | Encoded metadata list |

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

 - [BlockHashLoc home page](http://mark0.net/soft-blockhashloc-e.html)
 - [BlockHashLoc GitHub repository](https://github.com/MarcoPon/BlockHashLoc)

## Contacts

If you need more info, want to get in touch, or donate: [Marco Pontello](http://mark0.net/contacts-e.html)

**Bitcoin**: 1Mark1tF6QGj112F5d3fQALGf41YfzXEK3

![Qr-Code](http://mark0.net/images/qrcode.png) 