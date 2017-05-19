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
import zlib
import sqlite3

PROGRAM_VER = "0.7.4a"
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
    parser.add_argument("imgfilename", action="store", nargs="+",
                        help="image(s)/volumes(s) to scan")
    parser.add_argument("-db", "--database", action="store", dest="dbfilename",
                        metavar="filename",
                        help="temporary db with recovery info",
                        default="bhlreco.db3")
    parser.add_argument("-bhl", action="store", nargs="+", dest="bhlfilename", 
                        help="BHL file(s)", metavar="filename")
    parser.add_argument("-d", action="store", dest="destpath",
                        help="destination path", default="", metavar="path")
    parser.add_argument("-st", "--step", type=int, default=0,
                        help=("scan step"), metavar="n")
    res = parser.parse_args()
    return res


def errexit(errlev=1, mess=""):
    """Display an error and exit."""
    if mess != "":
        sys.stderr.write("%s: error: %s\n" %
                         (os.path.split(sys.argv[0])[1], mess))
    sys.exit(errlev)


def mcd(nums):
    """MCD: step good for different blocksizes"""
    res = min(nums)
    while res > 0:
        ok = 0
        for n in nums:
            if n % res != 0:
                break
            else:
                ok += 1
        if ok == len(nums):
            break
        res -= 1
    return res if res > 0 else 1


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


class RecDB():
    """Helper class to access Sqlite3 DB with recovery info"""

    def __init__(self, dbfilename):
        self.connection = sqlite3.connect(dbfilename)
        self.cursor = self.connection.cursor()

    def Commit(self):
        self.connection.commit()

    def CreateTables(self):
        c = self.cursor
        c.execute("CREATE TABLE bhl_files (id INTEGER, blocksize INTEGER, size INTEGER, name TEXT, datetime INTEGER, lastblock BLOB)")
        c.execute("CREATE TABLE bhl_hashlist (hash BLOB, fileid INTEGER, sourceid INTEGER, num INTEGER, pos INTEGER)")
        c.execute("CREATE INDEX hash ON bhl_hashlist (hash)")
        self.connection.commit()

    def SetFileData(self, fid=0, fblocksize=0, fsize=0, fname="", fdatetime=0, flastblock=b""):
        c = self.cursor
        c.execute("INSERT INTO bhl_files (id, blocksize, size, name, datetime, lastblock) VALUES (?, ?, ?, ?, ?, ?)",
                  (fid, fblocksize, fsize, fname, fdatetime, flastblock))
        self.connection.commit()

    def AddHash(self, fhash=0, fid=0, fnum=0):
        c = self.cursor
        c.execute("INSERT INTO bhl_hashlist (hash, fileid, num) VALUES (?, ?, ?)",
                  (fhash, fid, fnum))

    def SetHashPos(self, fhash=0, sid=0, pos=0):
        c = self.cursor
        c.execute("UPDATE bhl_hashlist SET pos = ?, sourceid = ? WHERE hash = ? AND pos IS NULL",
                  (pos, sid, fhash))
        return c.rowcount

    def GetFileInfo(self, fid):
        c = self.cursor
        data = {}
        c.execute("SELECT * FROM bhl_files where id = %i" % fid)
        res = c.fetchone()
        if res:
            data["blocksize"] = res[1]
            data["filesize"] = res[2]
            data["filename"] = res[3]
            data["filedatetime"] = res[4]
            data["lastblock"] = res[5]
        return data

    def GetWriteList(self, fid):
        c = self.cursor
        data = []
        c.execute("SELECT num, sourceid, pos FROM bhl_hashlist WHERE fileid = %i AND pos IS NOT NULL ORDER BY num" % fid)
        return c.fetchall()

def uniquifyFileName(filename):
    count = 0
    uniq = ""
    name,ext = os.path.splitext(filename)
    while os.path.exists(filename):
        count += 1
        uniq = "(%i)" % count
        filename = name + uniq + ext
    return filename


def main():

    cmdline = get_cmdline()
    print(cmdline)    

    #prepare database
    dbfilename = cmdline.dbfilename
    print("creating '%s' database..." % (dbfilename))
    if dbfilename.upper() != ":MEMORY:":
        open(dbfilename, 'w').close()
    db = RecDB(dbfilename)
    db.CreateTables()

    globalblocksnum = 0
    bhlfileid = 0
    sizelist = []

    for bhlfilename in cmdline.bhlfilename:
        if not os.path.exists(bhlfilename):
            errexit(1, "BHL file '%s' not found" % (bhlfilename))
        bhlfilesize = os.path.getsize(bhlfilename)

        #read hashes in memory
        blocklist = {}
        print("reading BHL file '%s'..." % bhlfilename)
        fin = open(bhlfilename, "rb", buffering=1024*1024)
        if BHL_MAGIC != fin.read(13):
            errexit(1, "not a valid BHL file")
        #check ver
        bhlver = ord(fin.read(1))
        blocksize = int.from_bytes(fin.read(4), byteorder='big')
        if not blocksize in sizelist:
            sizelist.append(blocksize)
        filesize = int.from_bytes(fin.read(8), byteorder='big')
        lastblocksize = filesize % blocksize
        totblocksnum = (filesize + blocksize-1) // blocksize

        #parse metadata section
        metasize = int.from_bytes(fin.read(4), byteorder='big')
        metadata = metadataDecode(fin.read(metasize))

        #read all block hashes
        globalhash = hashlib.sha256()
        for block in range(totblocksnum):
            digest = fin.read(32)
            globalhash.update(digest)
            if digest in blocklist:
                blocklist[digest].append(block)
            else:
                blocklist[digest] = [block]
        lastblockdigest = digest

        #verify the hashes read
        digest = fin.read(32)
        if globalhash.digest() != digest:
            errexit(1, "hashes block corrupt!")

        #read and check last blocks
        if lastblocksize:
            totblocksnum -= 1
            buffer = fin.read(bhlfilesize-fin.tell()+1)
            lastblockbuffer = zlib.decompress(buffer)
            blockhash = hashlib.sha256()
            blockhash.update(lastblockbuffer)
            if blockhash.digest() != lastblockdigest:
                errexit(1, "last block corrupt!")
            #remove lastblock from the list
            del blocklist[lastblockdigest]
        else:
            lastblockbuffer = b""

        globalblocksnum += totblocksnum

        #put data in the DB
        #hashes
        for digest in blocklist:
            for pos in blocklist[digest]:
                db.AddHash(fhash=digest, fid=bhlfileid, fnum=pos)
        #file info
        db.SetFileData(fid=bhlfileid, fblocksize=blocksize, fsize=filesize,
                       fname=metadata["filename"],
                       fdatetime=metadata["filedatetime"],
                       flastblock=lastblockbuffer)
        bhlfileid +=1


    #this list need to include all block sizes...
    maxblocksize = max(sizelist)
    print("Max block size:", maxblocksize)
    scanstep = cmdline.step
    if scanstep == 0:
        scanstep = mcd(sizelist)
    print("Scan step:", scanstep)

    #start scanning process...
    blocksfound = 0
    for imgfileid in range(len(cmdline.imgfilename)):
        imgfilename = cmdline.imgfilename[imgfileid]
        if not os.path.exists(imgfilename):
            errexit(1, "image file/volume '%s' not found" % (imgfilename))
        imgfilesize = os.path.getsize(imgfilename)

        print("scanning file '%s'..." % imgfilename)
        fin = open(imgfilename, "rb", buffering=1024*1024)

        updatetime = time.time() - 1
        starttime = time.time()
        writelist = {}
        docommit = False

        for pos in range(0, imgfilesize, scanstep):
            fin.seek(pos, 0)
            buffer = fin.read(maxblocksize)
            if len(buffer) > 0:
                #need to check for all sizes
                for size in sizelist:
                    blockhash = hashlib.sha256()
                    blockhash.update(buffer[:size])
                    digest = blockhash.digest()
                    if db.SetHashPos(fhash=digest, sid=imgfileid, pos=pos):
                        docommit = True
                        blocksfound += 1

                #status update
                if ((time.time() > updatetime) or (globalblocksnum == blocksfound) or
                    (imgfilesize-pos-len(buffer) == 0) ):
                    etime = (time.time()-starttime)
                    if etime == 0:
                        etime = .001
                    print("  %.1f%% - tot: %i - found: %i - %.2fMB/s" %
                          ((pos+len(buffer)-1)*100/imgfilesize,
                           globalblocksnum, blocksfound, pos/(1024*1024)/etime),
                          end = "\r", flush=True)
                    updatetime = time.time() + .2
                    if docommit:
                        db.Commit()
                        docommit = False
                    #break early if all the work is done
                    if blocksfound == globalblocksnum:
                        break
        fin.close()
        print()
        
    print("scan completed.")

    #open all the sources
    finlist = {}
    for imgfileid in range(len(cmdline.imgfilename)):
        finlist[imgfileid] = open(cmdline.imgfilename[imgfileid], "rb")

    #start rebuilding files...
    for fid in range(len(cmdline.bhlfilename)):
        fileinfo = db.GetFileInfo(fid)
        filename = fileinfo["filename"]
        filename = os.path.join(cmdline.destpath, filename)
        print("creating file '%s'..." % filename)
        open(filename, 'w').close()
        fout = open(filename, "wb")

        #get list of blocks num & positions
        blocksize = fileinfo["blocksize"]
        lastblock = fileinfo["lastblock"]
        writelist = db.GetWriteList(fid)
        for data in writelist:
            blocknum = data[0]
            imgid = data[1]
            pos = data[2]
            finlist[imgid].seek(pos)
            buffer = finlist[imgid].read(blocksize)
            fout.seek(blocknum*blocksize)
            fout.write(buffer)
        fout.write(lastblock)
        fout.close()
        
        if "filedatetime" in fileinfo:
            os.utime(filename,
                     (int(time.time()), fileinfo["filedatetime"]))


    errexit(1)

#################################

    #rebuild files
    print("creating file '%s'..." % filename)
    open(filename, 'w').close()
    fout = open(filename, "wb")

    filehash = hashlib.sha256()
    for blocknum in sorted(writelist):
        #todo: add missing blocks check...
        pos = writelist[blocknum]
        fin.seek(pos)
        buffer = fin.read(blocksize)
        fout.seek(blocknum*blocksize)
        fout.write(buffer)
        #hash check
        blockhash = hashlib.sha256()
        blockhash.update(buffer)
        filehash.update(blockhash.digest())
    if lastblocksize:
        #fout.seek(0, os.SEEK_END)
        fout.seek((totblocksnum-1)*blocksize)
        fout.write(lastblockbuffer)
        blockhash = hashlib.sha256()
        blockhash.update(lastblockbuffer)
        filehash.update(blockhash.digest())

    fout.close()
    fin.close()

    if filehash.digest() == globalhash.digest():
        print("hash match!")
    else:
        errexit(1, "hash mismatch! decoded file corrupted!")


if __name__ == '__main__':
    main()
