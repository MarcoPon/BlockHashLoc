#!/usr/bin/env python3

#--------------------------------------------------------------------------
# BHLReco - BlockHashLoc Recover
#
# Created: 06/05/2017
#
# Copyright (C) 2017 Marco Pontello - http://mark0.net/
#
# Licence:
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#--------------------------------------------------------------------------

import os
import sys
import hashlib
import argparse
import time

PROGRAM_VER = "0.5.3a"
BHL_VER = 1
BHL_MAGIC = b"BlockHashLoc\x1a"

def get_cmdline():
    """Evaluate command line parameters, usage & help."""
    parser = argparse.ArgumentParser(
             description="create a SeqBox container",
             formatter_class=argparse.ArgumentDefaultsHelpFormatter,
             prefix_chars='-+')
    parser.add_argument("-v", "--version", action='version', 
                        version='BlockHashLoc ' +
                        'Recover v%s - (C) 2017 by M.Pontello' % PROGRAM_VER) 
    parser.add_argument("imgfilename", action="store", 
                        help="image/volume to scan")
    parser.add_argument("bhlfilename", action="store", 
                        help="BHL file")
    parser.add_argument("filename", action="store", nargs='?', 
                        help="target/to recover file")
    parser.add_argument("-o", "--overwrite", action="store_true", default=False,
                        help="overwrite existing file")
    res = parser.parse_args()
    return res


def errexit(errlev=1, mess=""):
    """Display an error and exit."""
    if mess != "":
        sys.stderr.write("%s: error: %s\n" %
                         (os.path.split(sys.argv[0])[1], mess))
    sys.exit(errlev)
    

def metadataDecode(data):
    """Decode metadata"""
    metadata = {}
    p = 0
    while p < (len(data)-3):
        metaid = data[p:p+3]
        p+=3
        metalen = data[p]
        metabb = data[p+1:p+1+metalen]
        p = p + 1 + metalen    
        if metaid == b'FNM':
            metadata["filename"] = metabb.decode('utf-8')
        elif metaid == b'FDT':
            metadata["filedatetime"] = int.from_bytes(metabb, byteorder='big')

    return metadata


def main():

    cmdline = get_cmdline()

    imgfilename = cmdline.imgfilename
    if not os.path.exists(imgfilename):
        errexit(1, "image file/volume '%s' not found" % (imgfilename))
    imgfilesize = os.path.getsize(imgfilename)

    filename = cmdline.filename
    bhlfilename = cmdline.bhlfilename
    if not os.path.exists(bhlfilename):
        errexit(1, "BHL file '%s' not found" % (bhlfilename))
    filesize = os.path.getsize(bhlfilename)

    #read hashes in memory
    blocklist = {}
    print("Reading BHL file '%s'..." % bhlfilename)
    fin = open(bhlfilename, "rb", buffering=1024*1024)
    if BHL_MAGIC != fin.read(13):
        errexit(1, "Not a valid BHL file")
    #check ver
    bhlver = ord(fin.read(1))
    blocksize = int.from_bytes(fin.read(4), byteorder='big')
    filesize = int.from_bytes(fin.read(8), byteorder='big')
    lastblocksize = filesize % blocksize
    totblocksnum = (filesize + blocksize-1) // blocksize

    #parse metadata section
    metasize = int.from_bytes(fin.read(4), byteorder='big')
    metadata = metadataDecode(fin.read(metasize))

    #evaluate target filename
    if not filename:
        if "filename" in metadata:
            filename = metadata["filename"]
        else:
            filename = os.path.split(sbxfilename)[1] + ".out"
    elif os.path.isdir(filename):
        if "filename" in metadata:
            filename = os.path.join(filename, metadata["filename"])
        else:
            filename = os.path.join(filename,
                                    os.path.split(sbxfilename)[1] + ".out")
    if os.path.exists(filename) and not cmdline.overwrite:
        errexit(1, "target file '%s' already exists!" % (filename))

    globalhash = hashlib.sha256()
    for block in range(totblocksnum):
        digest = fin.read(32)
        globalhash.update(digest)
        if digest in blocklist:
            blocklist[digest].append(block)
        else:
            blocklist[digest] = [block]

    #verify the hashes read
    digest = fin.read(32)
    if globalhash.digest() != digest:
        errexit(1, "hash block corrupt!")

    #start scanning and recovering process...
    print("scanning file '%s'..." % imgfilename)
    fin = open(imgfilename, "rb", buffering=1024*1024)
    print("creating file '%s'..." % filename)
    open(filename, 'w').close()
    fout = open(filename, "wb")

    updatetime = time.time() - 1
    starttime = time.time()
    wrotelist = {}
    blocksfound = 0
    while True:
        buffer = fin.read(blocksize)
        if len(buffer) > 0:
            blockhash = hashlib.sha256()
            blockhash.update(buffer)
            digest = blockhash.digest()
            if digest in blocklist:
                for blocknum in blocklist[digest]:
                    if blocknum not in wrotelist:
                        fout.seek(blocknum*blocksize)
                        fout.write(buffer)
                        wrotelist[blocknum] = 1
                        blocksfound += 1
            else:
                blockhash = hashlib.sha256()
                blockhash.update(buffer[:lastblocksize])
                digest = blockhash.digest()
                if digest in blocklist:
                    for blocknum in blocklist[digest]:
                        if blocknum not in wrotelist:
                            fout.seek(blocknum*blocksize)
                            fout.write(buffer[:lastblocksize])
                            wrotelist[blocknum] = 1
                            blocksfound += 1

            #status update
            pos = fin.tell()
            if ((time.time() > updatetime) or (totblocksnum == blocksfound) or
                (pos == imgfilesize)):
                etime = (time.time()-starttime)
                if etime == 0:
                    etime = .1
                print("  %.1f%% - tot: %i - found: %i - %.2fMB/s" %
                      (pos*100/imgfilesize, totblocksnum, blocksfound,
                       pos/(1024*1024)/etime), end = "\r", flush=True)
                updatetime = time.time() + .2

        else:
            break
    
    fout.close()
    fin.close()
    if "filedatetime" in metadata:
        os.utime(filename,
                 (int(time.time()), metadata["filedatetime"]))
    print("\nrecovery completed.")


if __name__ == '__main__':
    main()
