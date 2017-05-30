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
import zlib

PROGRAM_VER = "0.7.0a"
BHL_VER = 1

def get_cmdline():
    """Evaluate command line parameters, usage & help."""
    parser = argparse.ArgumentParser(
             description="create a SeqBox container",
             formatter_class=argparse.ArgumentDefaultsHelpFormatter,
             prefix_chars='-', fromfile_prefix_chars='@')
    parser.add_argument("-v", "--version", action='version', 
                        version='BlockHashLoc ' +
                        'Maker v%s - (C) 2017 by M.Pontello' % PROGRAM_VER) 
    parser.add_argument("filename", action="store", nargs="+",
                        help="file to process")
    parser.add_argument("-d", action="store", dest="destpath",
                        help="destination path", default="", metavar="path")
    parser.add_argument("-b", "--blocksize", type=int, default=512,
                        help="blocks size", metavar="n")
    parser.add_argument("-c", "--continue", action="store_true", default=False,
                        help="continue on block errors", dest="cont")
    res = parser.parse_args()
    return res


def errexit(errlev=1, mess=""):
    """Display an error and exit."""
    if mess != "":
        sys.stderr.write("%s: error: %s\n" %
                         (os.path.split(sys.argv[0])[1], mess))
    sys.exit(errlev)


def buildBHL(filename, bhlfilename, blocksize):
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
    bufferz = b""
    while True:
        buffer = fin.read(blocksize)
        if len(buffer) < blocksize:
            if len(buffer) == 0:
                break
            else:
                #compressed blob with last block remainder
                bufferz = zlib.compress(buffer, 9)
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
        
    #write hash of hashes and block remainder (if present)
    fout.write(globalhash.digest())
    if len(bufferz):
        fout.write(bufferz)
    
    fin.close()
    fout.close()

    #show stats about the file just created
    bhlfilesize = os.path.getsize(bhlfilename)
    overhead = bhlfilesize * 100 / filesize
    print("  BHL file size: %i - blocks: %i - ratio: %.1f%%" %
          (bhlfilesize, blocksnum, overhead))


def main():

    cmdline = get_cmdline()
    blocksize = cmdline.blocksize

    bhlok = 0
    bhlerr = 0

    for filename in cmdline.filename:
        if not os.path.exists(filename):
            errexit(1, "file '%s' not found" % (filename))
 
        destpath = cmdline.destpath
        if not destpath:
            bhlfilename = os.path.split(filename)[1] + ".bhl"
        else:
            if not os.path.isdir(destpath):
                destpath = os.path.split(filename)[0]
            bhlfilename = os.path.join(destpath,
                                       os.path.split(filename)[1] + ".bhl")

        try:
            buildBHL(filename, bhlfilename, blocksize)
            bhlok += 1
        except:
            if cmdline.cont:
                bhlerr += 1
                print("  warning: can't create BHL file!")
            else:
                errexit(1, "can't creating BHL file '%s'" % (bhlfilename))

        if len(cmdline.filename) > 1 and bhlerr > 0:
            print("\nBHL files created: %i - errors: %i" % (bhlok, bhlerr))            


if __name__ == '__main__':
    main()
