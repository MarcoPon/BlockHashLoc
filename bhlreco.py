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

PROGRAM_VER = "0.7.1a"
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
    parser.add_argument("-d", action="store", 
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
        c.execute("CREATE TABLE bhl_sources (id INTEGER, name TEXT)")
        c.execute("CREATE TABLE bhl_files (id INTEGER, blocksize INTEGER, size INTEGER, name TEXT, datetime INTEGER, lastblock BLOB)")
        c.execute("CREATE TABLE bhl_hashlist (hash BLOB, fileid INTEGER, num INTEGER, pos INTEGER)")
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

    def SetHashPos(self, fhash=0, pos=0):
        c = self.cursor
        c.execute("UPDATE bhl_hashlist SET pos = ? WHERE hash = ?",
                  (pos, fhash))

##old db methods as a reference
        
    def GetMetaFromUID(self, uid):
        meta = {}
        c = self.cursor
        c.execute("SELECT * from sbx_meta where uid = '%i'" % uid)
        res = c.fetchone()
        if res:
            meta["filesize"] = res[1]
            meta["filename"] = res[2]
            meta["filedatetime"] = res[3]
        return meta

    def GetUIDFromFileName(self, filename):
        c = self.cursor
        c.execute("select uid from sbx_meta where name = '%s'" % (filename))
        res = c.fetchone()
        if res:
            return(res[0])

    def GetBlocksList(self, uid):
        c = self.cursor
        c.execute("SELECT num, fileid, pos from sbx_blocks where uid = '%i' group by num order by num" % (uid))
        return c.fetchall()

    def GetUIDDataList(self):
        c = self.cursor
        c.execute("SELECT * from sbx_uids")
        res = {row[0]:row[1] for row in c.fetchall()}
        return res

    def GetSourcesList(self):
        c = self.cursor
        c.execute("SELECT * FROM sbx_source")
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
    dbfilename = cmdline.dbfilename

    #prepare database
    print("creating '%s' database..." % (dbfilename))
    open(dbfilename, 'w').close()
    db = RecDB(dbfilename)
    db.CreateTables()

    i = 0
    for bhlfilename in cmdline.bhlfilename:
        i+=1
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
            buffer = fin.read(bhlfilesize-fin.tell()+1)
            lastblockbuffer = zlib.decompress(buffer)
            blockhash = hashlib.sha256()
            blockhash.update(lastblockbuffer)
            if blockhash.digest() != lastblockdigest:
                errexit(1, "last block corrupt!")
        else:
            lastblockbuffer = b""

        #put data in the DB
        #hashes
        for digest in blocklist:
            for pos in blocklist[digest]:
                db.AddHash(fhash=digest, fid=i, fnum=pos)
        #file info
        db.SetFileData(fid=i, fblocksize=blocksize, fsize=filesize,
                       fname=metadata["filename"],
                       fdatetime=metadata["filedatetime"],
                       flastblock=lastblockbuffer)
        
    errexit(1)


##    imgfilename = cmdline.imgfilename
##    if not os.path.exists(imgfilename):
##        errexit(1, "image file/volume '%s' not found" % (imgfilename))
##    imgfilesize = os.path.getsize(imgfilename)

##    filename = cmdline.filename




##    #evaluate target filename
##    if not filename:
##        if "filename" in metadata:
##            filename = metadata["filename"]
##        else:
##            filename = os.path.split(sbxfilename)[1] + ".out"
##    elif os.path.isdir(filename):
##        if "filename" in metadata:
##            filename = os.path.join(filename, metadata["filename"])
##        else:
##            filename = os.path.join(filename,
##                                    os.path.split(sbxfilename)[1] + ".out")
##    if os.path.exists(filename) and not cmdline.overwrite:
##        errexit(1, "target file '%s' already exists!" % (filename))
##



    scanstep = cmdline.step
    if scanstep == 0:
        scanstep = blocksize

    #start scanning process...
    print("scanning file '%s'..." % imgfilename)
    fin = open(imgfilename, "rb", buffering=1024*1024)

    updatetime = time.time() - 1
    starttime = time.time()
    writelist = {}

    #this list need to include all block sizes...
    sizelist = [blocksize]
    
    for pos in range(0, imgfilesize, scanstep):
        fin.seek(pos, 0)
        buffer = fin.read(blocksize)
        if len(buffer) > 0:
            #need to check for all sizes
            for size in sizelist:
                blockhash = hashlib.sha256()
                blockhash.update(buffer[:size])
                digest = blockhash.digest()
                if digest in blocklist:
                    for blocknum in blocklist[digest]:
                        if blocknum not in writelist:
                            writelist[blocknum] = pos

            #status update
            blocksfound = len(writelist)
            if ((time.time() > updatetime) or (totblocksnum == blocksfound) or
                (imgfilesize-pos-len(buffer) == 0) ):
                etime = (time.time()-starttime)
                if etime == 0:
                    etime = .001
                print("  %.1f%% - tot: %i - found: %i - %.2fMB/s" %
                      ((pos+len(buffer)-1)*100/imgfilesize,
                       totblocksnum, blocksfound, pos/(1024*1024)/etime),
                      end = "\r", flush=True)
                updatetime = time.time() + .2
                #break early if all the work is done
                if totblocksnum == blocksfound:
                    break

    print("\nscan completed.")

    #rebuild file
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

    if "filedatetime" in metadata:
        os.utime(filename,
                 (int(time.time()), metadata["filedatetime"]))

    if filehash.digest() == globalhash.digest():
        print("hash match!")
    else:
        errexit(1, "hash mismatch! decoded file corrupted!")


if __name__ == '__main__':
    main()
