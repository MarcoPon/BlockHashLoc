#!/usr/bin/env python3

#--------------------------------------------------------------------------
# BHLReco - Block Hash Locator recover
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
from time import time

PROGRAM_VER = "0.3a"
BHL_VER = 1
BHL_MAGIC = b"Block Hash Locator\x1a"

def get_cmdline():
    """Evaluate command line parameters, usage & help."""
    parser = argparse.ArgumentParser(
             description="create a SeqBox container",
             formatter_class=argparse.ArgumentDefaultsHelpFormatter,
             prefix_chars='-+')
    parser.add_argument("-v", "--version", action='version', 
                        version='Block Hash Locator ' +
                        'Recover v%s - (C) 2017 by M.Pontello' % PROGRAM_VER) 
    parser.add_argument("imgfilename", action="store", 
                        help="image/volume to scan")
    parser.add_argument("bhlfilename", action="store", 
                        help="BHL file")
    parser.add_argument("filename", action="store", 
                        help="file to recover")
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
    

def main():

    cmdline = get_cmdline()

    imgfilename = cmdline.imgfilename
    if not os.path.exists(imgfilename):
        errexit(1, "image file/volume '%s' not found" % (imgfilename))

    filename = cmdline.filename
    if os.path.exists(filename) and not cmdline.overwrite:
        errexit(1, "file '%s' already exists!" % (filename))

    bhlfilename = cmdline.bhlfilename
    if not os.path.exists(bhlfilename):
        errexit(1, "BHL file '%s' not found" % (bhlfilename))
    filesize = os.path.getsize(bhlfilename)

    #read hashes in memory
    blocklist = {}
    print("Reading BHL file '%s'..." % bhlfilename)
    fin = open(bhlfilename, "rb", buffering=1024*1024)
    if BHL_MAGIC != fin.read(19):
        errexit(1, "Not a valid BHL file")
    #check ver
    bhlver = ord(fin.read(1))
    blocksize = int.from_bytes(fin.read(4), byteorder='big')
    filesize = int.from_bytes(fin.read(8), byteorder='big')

    lastblocksize = filesize % blocksize
    totblocksnum = (filesize + blocksize-1) // blocksize

    for block in range(totblocksnum):
        digest = fin.read(32)
        if digest in blocklist:
            blocklist[digest].append(block)
        else:
            blocklist[digest] = [block]

    #start scanning...
    print("scanning file '%s'..." % imgfilename)
    fin = open(imgfilename, "rb", buffering=1024*1024)
    print("creating file '%s'..." % filename)
    fout = open(filename, "wb")

    updatetime = time() - 1
    starttime = time()
    wrotelist = {}
    blocksfound = 0
    while True:
        buffer = fin.read(blocksize)
        if len(buffer) < blocksize:
            break
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
        if (time() > updatetime):
            pos = fin.tell()
            etime = (time()-starttime)
            if etime == 0:
                etime = 1
            print("pos: %i - tot: %i - found: %i - %.2fMB/s" %
                  (pos, totblocksnum, blocksfound, pos/(1024*1024)/etime),
                  end = "\r", flush=True)
            updatetime = time() + .2

            if totblocksnum == blocksfound:
               break
    
    fout.close()
    fin.close()


if __name__ == '__main__':
    main()
