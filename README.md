# BlockHashLoc

The purpose of BlockHashLoc is to enable the recovery of files after total loss of the file system structure, or without even knowing what File System was used in the first place.

The way it can recover a given file is by keeping a (small) parallel BHL file with a list of crypto-hash of all the blocks (of selectable size) that compose it. So it's possible to read the blocks of a (set of) disk image(s)/volume(s), calculate their hashes, compare with the saved ones and rebuild the original file. 

With adequately sized blocks (512 bytes, 4KB, etc. depending on the media and File System), this let one recover a file regardless of the FS used, or the FS integrity, or the fragmentation level.

This project is related to [SeqBox](https://github.com/MarcoPon/SeqBox). The main differences are:

- SeqBox create a stand-alone file container with the above listed recovery characteristics.
 
- BHL realize the same effect with a (small) parallel file, that can be stored separately (in other media, or in the cloud), or along the original as a SeqBox file (so that it can be recovered too, as the first step), so it can be used to add a degree of recoverability to existing files.

**N.B.**

The tools are still in beta and surely not speed optimized, but they are already functional and the BHL file format is considered final.

## Demo tour

BlockHashLoc is composed of two separate tools:
 - BHLMake: create BHL files 
 - BHLReco: recover files searching for the block's hashes contained in a set of BHL files
  
There are in some case many parameters but the default are sensible so it's generally pretty simple.

Here's a practical example. Let's see how 2 photos can be recovered from a fragmented floppy disk that have lost its FAT (and any other system section). The 2 JPEGs weight about 450KB and 680KB:

![Manu01](http://i.imgur.com/QKxgT5r.jpg) ![Manu02](http://i.imgur.com/jfQLlx1.jpg)

We start by creating the BHL files, and then proceed to test them to make sure they are all right:

```
c:\t>bhlmake *.jpg
creating file 'Manu01.jpg.bhl'...
  BHL file size: 29582 - blocks: 913 - ratio: 6.3%
creating file 'Manu02.jpg.bhl'...
  BHL file size: 43936 - blocks: 1363 - ratio: 6.3%
  
c:\t>bhlreco -t -bhl *.bhl
reading BHL file 'Manu01.jpg.bhl'...
reading BHL file 'Manu02.jpg.bhl'...
BHL file(s) OK!

```

Now we put both the JPEGs in a floppy disk image that have gone trough various cycles of files updating and deleting. At this point the BHL files could be kept somewhere else (another disk, some online storage, etc.), or put in the same disk image after being encoded in one or more [SeqBox](https://github.com/MarcoPon/SeqBox) recoverable container(s) - because, obviously, there's no use in making BHL files if they can be lost too.
As a result the data is laid out like this:

![Disk Layout](http://i.imgur.com/3MUOAjk.png)

The photos are in green, and the two SBX files in blue.
Then with an hex editor we zap the first system sectors and the FAT (in red), making the disk image unreadable!
Time for recovery!

We start with the free (GPLV v2+) [PhotoRec](http://www.cgsecurity.org/wiki/PhotoRec), which is the go-to tool for these kind of jobs. Parameters are set to "Paranoid : YES (Brute force enabled)" & "Keep corrupted files : Yes", to search the entire data area. 
As the files are fragmented, we know we can't expect miracles. The starting sector of the photos will be surely found, but as soon as the first contiguous fragment end, it's anyone guess.

![PhotoRec results](http://i.imgur.com/y9phKLX.png)

As expected, something has been recovered. But the 2 files sizes are off (32K and 340KB). The very first parts of the photos are OK, but then they degrade quickly as other random blocks of data where mixed in. We have all seen JPEGs ending up like this:

![Manu01](http://i.imgur.com/bCtYJpW.jpg) ![Manu02](http://i.imgur.com/EmOid42.jpg)

Other popular recovery tools lead to the same results. It's not anyone fault: it's just not possible to know how the various fragment are concatenated, without an index or some kind of list (there are approaches based on file type validators that can in at least some cases differentiate between spurious and *valid* blocks, but that's beside the point).

But having the BHL files at hand, it's a different story. Each of the blocks referenced in the BHL files can't be fragmented, and they all can be located anywhere in the disk just by calculating the hash of every blocks until all matching ones are found. 

So, the first thing we need is to obtain the BHL files, either by getting them from some alternate storage, or recovering the [SeqBox](https://github.com/MarcoPon/SeqBox) containers from the same disk image and extracting them.

Then we can run BHLReco and begin the scanning process:

```
c:\t>bhlreco disk.IMA -bhl *.bhl
creating ':memory:' database...
reading BHL file 'Manu01.jpg.bhl'...
updating db...
reading BHL file 'Manu02.jpg.bhl'...
updating db...
scan step: 512
scanning file 'disk.IMA'...
  90.4% - tot: 2274 - found: 2274 - 40.65MB/s
scan completed.
creating file 'Manu01.jpg'...
hash match!
creating file 'Manu02.jpg'...
hash match!

files restored: 2 - with errors: 0 - files missing: 0
```

All files have been recovered, with no errors!
Time for a quick visual check:

![Manu01](http://i.imgur.com/qEB9wBQ.jpg) ![Manu02](http://i.imgur.com/s6spyFq.jpg)

N.B. Here's a [7-Zip archive](http://mark0.net/download/bhldemo-diskimage.7z) with the disk image and the 2 BHL files used in the demo (1.2MB).



## Tech spec

Byte order: Big Endian

Hash: SHA-256

### BHL file structure

| section    | desc                                 | note      |
| ---------- | ------------------------------------ | --------- |
| Header     | Signature & version                  |           |
| Metadata   | Misc info                            |           |
| Hash       | Blocks hash list & final hash        |           |
| Last block | zlib compressed last block remainder | if needed |


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
| FNM | filename (utf-8)                           |
| FDT | date & time (8 bytes, seconds since epoch) |

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