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
import glob

PROGRAM_VER = "0.7.17b"
BHL_VER = 1
BHL_MAGIC = b"BlockHashLoc\x1a"

def get_cmdline():
    """Evaluate command line parameters, usage & help."""
    parser = argparse.ArgumentParser(
             description="create a SeqBox container",
             formatter_class=argparse.ArgumentDefaultsHelpFormatter,
             prefix_chars='-+', fromfile_prefix_chars='@')
    parser.add_argument("-v", "--version", action='version', 
                        version='BlockHashLoc ' +
                        'Recover v%s - (C) 2017 by M.Pontello' % PROGRAM_VER) 
    parser.add_argument("imgfilename", action="store", nargs="*",
                        help="image(s)/volumes(s) to scan")
    parser.add_argument("-db", "--database", action="store", dest="dbfilename",
                        metavar="filename",
                        help="temporary db with recovery info",
                        default=":memory:")
    parser.add_argument("-bhl", action="store", nargs="+", dest="bhlfilename", 
                        help="BHL file(s)", metavar="filename", required=True)
    parser.add_argument("-d", action="store", dest="destpath",
                        help="destination path", default="", metavar="path")
    parser.add_argument("-o", "--offset", type=int, default=0,
                        help=("offset from the start"), metavar="n")
    parser.add_argument("-st", "--step", type=int, default=0,
                        help=("scan step"), metavar="n")
    parser.add_argument("-t","--test", action="store_true", default=False,
                        help="only test BHL file(s)")
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
        c.execute("CREATE TABLE bhl_files (id INTEGER, blocksize INTEGER, size INTEGER, name TEXT, datetime INTEGER, lastblock BLOB, hash BLOB)")
        c.execute("CREATE TABLE bhl_hashlist (hash BLOB, fileid INTEGER, sourceid INTEGER, num INTEGER, pos INTEGER)")
        c.execute("CREATE INDEX hash ON bhl_hashlist (hash)")
        self.connection.commit()

    def SetFileData(self, fid=0, fblocksize=0, fsize=0, fname="", fdatetime=0, flastblock=b"", fhash=b""):
        c = self.cursor
        c.execute("INSERT INTO bhl_files (id, blocksize, size, name, datetime, lastblock, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (fid, fblocksize, fsize, fname, fdatetime, flastblock, fhash))
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
            data["hash"] = res[6]
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


def getFileSize(filename):
    """Calc file size - works on devices too"""
    ftemp = os.open(filename, os.O_RDONLY)
    try:
        return os.lseek(ftemp, 0, os.SEEK_END)
    finally:
        os.close(ftemp)


def main():

    cmdline = get_cmdline()

    globalblocksnum = 0
    bhlfileid = 0
    sizelist = []

    if not len(cmdline.imgfilename) and not cmdline.test:
        errexit(1, "no image file/volume specified!")        

    #build list of BHL files to process
    bhlfilenames = []
    for filename in cmdline.bhlfilename:
        if os.path.isdir(filename):
            filename = os.path.join(filename, "*")
        bhlfilenames += glob.glob(filename)
    bhlfilenames = [filename for filename in bhlfilenames
                    if not os.path.isdir(filename)]
    bhlfilenames = sorted(set(bhlfilenames))

    if len(bhlfilenames) == 0:
        errexit(1, "no BHL file(s) found!")

    #prepare database
    if not cmdline.test:
        dbfilename = cmdline.dbfilename
        print("creating '%s' database..." % (dbfilename))
        if dbfilename.upper() != ":MEMORY:":
            open(dbfilename, 'w').close()
        db = RecDB(dbfilename)
        db.CreateTables()

    #process all BHL files
    for bhlfilename in bhlfilenames:
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
        updatetime = time.time() 
        for block in range(totblocksnum):
            digest = fin.read(32)
            globalhash.update(digest)
            if digest in blocklist:
                blocklist[digest].append(block)
            else:
                blocklist[digest] = [block]
            #some progress update
            if time.time() > updatetime:
                print("%.1f%%" % (fin.tell()*100.0/bhlfilesize), " ",
                      end="\r", flush=True)
                updatetime = time.time() + .1

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
        print("100%  ", end="\r", flush=True)

        globalblocksnum += totblocksnum

        #put data in the DB
        #hashes
        if not cmdline.test:
            print("updating db...")
            updatetime = time.time()
            i = 0
            for digest in blocklist:
                for pos in blocklist[digest]:
                    db.AddHash(fhash=digest, fid=bhlfileid, fnum=pos)
                i+= 1
                #some progress update
                if time.time() > updatetime:
                    print("%.1f%%" % (i*100.0/len(blocklist)), " ",
                          end="\r", flush=True)
                    db.Commit()
                    updatetime = time.time() + .1
                
            #file info
            db.SetFileData(fid=bhlfileid, fblocksize=blocksize, fsize=filesize,
                           fname=metadata["filename"],
                           fdatetime=metadata["filedatetime"],
                           flastblock=lastblockbuffer,
                           fhash=globalhash.digest())
        bhlfileid +=1

    if cmdline.test:
        print("BHL file(s) OK!")
        errexit(0)

    #select an adequate scan step
    maxblocksize = max(sizelist)
    scanstep = cmdline.step
    if scanstep == 0:
        scanstep = mcd(sizelist)
    print("scan step:", scanstep)
    offset = cmdline.offset

    #build list of image files to process
    imgfilenames = []
    for filename in cmdline.imgfilename:
        if os.path.isdir(filename):
            filename = os.path.join(filename, "*")
        imgfilenames += glob.glob(filename)
    imgfilenames = [filename for filename in imgfilenames
                    if not os.path.isdir(filename)]
    imgfilenames = sorted(set(imgfilenames))

    #start scanning process...
    blocksfound = 0
    for imgfileid in range(len(imgfilenames)):
        imgfilename = imgfilenames[imgfileid]
        if not os.path.exists(imgfilename):
            errexit(1, "image file/volume '%s' not found" % (imgfilename))
        imgfilesize = getFileSize(imgfilename)

        print("scanning file '%s'..." % imgfilename)
        fin = open(imgfilename, "rb", buffering=1024*1024)

        updatetime = time.time() - 1
        starttime = time.time()
        writelist = {}
        docommit = False

        for pos in range(offset, imgfilesize, scanstep):
            fin.seek(pos, 0)
            buffer = fin.read(maxblocksize)
            if len(buffer) > 0:
                #need to check for all sizes
                for size in sizelist:
                    blockhash = hashlib.sha256()
                    blockhash.update(buffer[:size])
                    digest = blockhash.digest()
                    num = db.SetHashPos(fhash=digest, sid=imgfileid, pos=pos)
                    if num:
                        docommit = True
                        blocksfound += num

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

    filesrestored = 0
    filesrestorederr = 0
    filesmissing= 0

    #open all the sources
    finlist = {}
    for imgfileid in range(len(imgfilenames)):
        finlist[imgfileid] = open(imgfilenames[imgfileid], "rb")

    #start rebuilding files...
    for fid in range(len(bhlfilenames)):
        fileinfo = db.GetFileInfo(fid)
        filename = fileinfo["filename"]
        filename = os.path.join(cmdline.destpath, filename)
        filesize = fileinfo["filesize"]

        #get list of blocks num & positions
        blocksize = fileinfo["blocksize"]
        lastblock = fileinfo["lastblock"]
        writelist = db.GetWriteList(fid)
        totblocksnum = filesize // blocksize

        if len(writelist) > 0 or totblocksnum == 0: 
            print("creating file '%s'..." % filename)
            open(filename, 'w').close()
            fout = open(filename, "wb")

            if len(writelist) < totblocksnum:
                print("file incomplete! block missings: %i" %
                      (totblocksnum - len(writelist)))

            filehash = hashlib.sha256()
            for data in writelist:
                blocknum = data[0]
                imgid = data[1]
                pos = data[2]
                finlist[imgid].seek(pos)
                buffer = finlist[imgid].read(blocksize)
                fout.seek(blocknum*blocksize)
                fout.write(buffer)
                blockhash = hashlib.sha256()
                blockhash.update(buffer)
                filehash.update(blockhash.digest())
            if lastblock:
                fout.write(lastblock)
                blockhash = hashlib.sha256()
                blockhash.update(lastblock)
                filehash.update(blockhash.digest())
            fout.close()
            if "filedatetime" in fileinfo:
                os.utime(filename,
                         (int(time.time()), fileinfo["filedatetime"]))
            filesrestored += 1

            if filehash.digest() == fileinfo["hash"]:
                print("hash match!")
            else:
                print("hash mismatch! decoded file corrupted/incomplete!")
                filesrestorederr += 1

        else:
            print("nothing found for file '%s'" % filename)
            filesmissing += 1

    print("\nfiles restored: %i - with errors: %i - files missing: %i" %
          (filesrestored, filesrestorederr, filesmissing))


if __name__ == '__main__':
    main()
