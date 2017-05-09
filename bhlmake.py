#!/usr/bin/env python3

#--------------------------------------------------------------------------
# BHLMake - BlockHashLoc Maker
#
# Created: 04/05/2017
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

PROGRAM_VER = "0.5.2a"
BHL_VER = 1

def get_cmdline():
    """Evaluate command line parameters, usage & help."""
    parser = argparse.ArgumentParser(
             description="create a SeqBox container",
             formatter_class=argparse.ArgumentDefaultsHelpFormatter,
             prefix_chars='-+')
    parser.add_argument("-v", "--version", action='version', 
                        version='BlockHashLoc ' +
                        'Maker v%s - (C) 2017 by M.Pontello' % PROGRAM_VER) 
    parser.add_argument("filename", action="store", 
                        help="file to encode")
    parser.add_argument("bhlfilename", action="store", nargs='?',
                        help="BHL file")
    parser.add_argument("-o", "--overwrite", action="store_true", default=False,
                        help="overwrite existing file")
    parser.add_argument("-b", "--blocksize", type=int, default=512,
                        help="blocks size", metavar="n")
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

    blocksize = cmdline.blocksize
    filename = cmdline.filename
    bhlfilename = cmdline.bhlfilename
    if not bhlfilename:
        bhlfilename = os.path.split(filename)[1] + ".bhl"
    elif os.path.isdir(bhlfilename):
        bhlfilename = os.path.join(bhlfilename,
                                   os.path.split(filename)[1] + ".bhl")
    if os.path.exists(bhlfilename) and not cmdline.overwrite:
        errexit(1, "BHL file '%s' already exists!" % (bhlfilename))
        
    if not os.path.exists(filename):
        errexit(1, "file '%s' not found" % (filename))
    filesize = os.path.getsize(filename)


    fin = open(filename, "rb", buffering=1024*1024)
    print("creating file '%s'..." % bhlfilename)
    open(bhlfilename, 'w').close()
    fout = open(bhlfilename, "wb", buffering=1024*1024)

    #write header
    fout.write(b"BlockHashLoc\x1a")
    fout.write(bytes([BHL_VER]))
    fout.write(blocksize.to_bytes(4, byteorder='big', signed=False))
    fout.write(filesize.to_bytes(8, byteorder='big', signed=False))

    #write metadata
    metadata = b""
    bb = os.path.split(filename)[1].encode()
    bb = b"FNM" + bytes([len(bb)]) + bb
    metadata += bb
    bb = int(os.path.getmtime(filename)).to_bytes(8, byteorder='big')
    bb = b"FDT" + bytes([len(bb)]) + bb
    metadata += bb

    metadata = len(metadata).to_bytes(4, byteorder='big') + metadata
    fout.write(metadata)

    #read blocks and calc hashes
    globalhash = hashlib.sha256()
    blocksnum = 0
    ticks = 0
    updatetime = time() 
    while True:
        buffer = fin.read(blocksize)
        if len(buffer) < blocksize:
            if len(buffer) == 0:
                break
        blockhash = hashlib.sha256()
        blockhash.update(buffer)
        digest = blockhash.digest()
        globalhash.update(digest)
        fout.write(digest)
        blocksnum += 1

        #some progress update
        if time() > updatetime:
            print("%.1f%%" % (fin.tell()*100.0/filesize), " ",
                  end="\r", flush=True)
            updatetime = time() + .1
        
    fout.write(globalhash.digest())
    print("100%  ")
    fin.close()
    fout.close()

    #show stats about the file just created
    bhlfilesize = os.path.getsize(bhlfilename)
    overhead = bhlfilesize * 100 / filesize
    print("BHL file size: %i - blocks: %i - ratio: %.1f%%" %
          (bhlfilesize, blocksnum, overhead))


if __name__ == '__main__':
    main()
