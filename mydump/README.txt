Programing Language C
Library used: LIBPCAP 
To run a file use command:
	mydump [-i interface] [-r FILENAME] [-s string] expression
	
	
Output for sample_input.pcap is saved in sample_output.txt
Output for Live capture is saved in live_capture_output.txt

Files Submitted:
1)mydump.c- source file
2)mydump.h -header file
3)makefile
4)sample_input.pcap - a test input file corresponding to which a sample_output is generated
5)sample_output.txt - Output for sample_input file
6)live_capture_output.txt - A sample output for a live capture
7)README: This file.

Design: USing the API's provided by libpcap, we are getting callbacks upon receiving a packet at specified interface or input file.
		Each callback gives 1 packet.
		The program prints the Header info as given by tcpdump (without -v option)
		The Program also prints Hex and string values for the packet as printed by tcpdump
		THIS PROGRAM ONLY PRINTS THE APPLICATION LAYER PACKET DETAILS AS EXPECTED IN QUESTION
		This is mostly a wrapper over the API's given by libpcap to display a tcpdump like functionality
		
		
		
Sample OUTPUT:
Below is a sample of OUTPUT produced by the program:		

Run as: mydump -i eth0 "http"

OUTPUT:

Mon Jul  8 17:23:58 2013 0:26:b0:ec:ce:28 -> f8:c0:1:7b:4d:d3 type 0x800 len 86 128.208.2.180  128.208.4.212  TCP
47 45 54 20 2f 73 70 64 79 2f 6f 62 6a 5f 31 30       GET /spdy/obj_10
30 42 2d 33 2e 6a 73 20 48 54 54 50 2f 31 2e 31       0B-3.js HTTP/1.1
0d 0a 48 6f 73 74 3a 20 75 6c 74 72 61 6c 69 73       ..Host: ultralis
6b 2e 63 73 2e 77 61 73 68 69 6e 67 74 6f 6e 2e       k.cs.washington.
                                                                      
Mon Jul  8 17:23:58 2013 0:26:b0:ec:ce:28 -> f8:c0:1:7b:4d:d3 type 0x800 len 490 128.208.2.180  128.208.4.212  TCP
48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d       HTTP/1.1 200 OK.
0a 44 61 74 65 3a 20 4d 6f 6e 2c 20 30 38 20 4a       .Date: Mon, 08 J
75 6c 20 32 30 31 33 20 32 31 3a 32 33 3a 35 35       ul 2013 21:23:55
20 47 4d 54 0d 0a 53 65 72 76 65 72 3a 20 41 70        GMT..Server: Ap
61 63 68 65 2f 32 2e 32 2e 32 32 20 28 55 62 75       ache/2.2.22 (Ubu
6e 74 75 29 0d 0a 4c 61 73 74 2d 4d 6f 64 69 66       ntu)..Last-Modif
69 65 64 3a 20 46 72 69 2c 20 32 34 20 4d 61 79       ied: Fri, 24 May
20 32 30 31 33 20 31 39 3a 31 35 3a 34 31 20 47        2013 19:15:41 G
4d 54 0d 0a 45 54 61 67 3a 20 22 36 36 30 66 33       MT..ETag: "660f3
31 2d 36 34 2d 34 64 64 37 62 39 66 66 34 35 64       1-64-4dd7b9ff45d
63 61 22 0d 0a 41 63 63 65 70 74 2d 52 61 6e 67       ca"..Accept-Rang
65 73 3a 20 62 79 74 65 73 0d 0a 43 6f 6e 74 65       es: bytes..Conte
6e 74 2d 4c 65 6e 67 74 68 3a 20 31 30 30 0d 0a       nt-Length: 100..
4b 65 65 70 2d 41 6c 69 76 65 3a 20 74 69 6d 65       Keep-Alive: time
6f 75 74 3d 35 2c 20 6d 61 78 3d 31 30 30 0d 0a       out=5, max=100..
43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70       Connection: Keep
2d 41 6c 69 76 65 0d 0a 43 6f 6e 74 65 6e 74 2d       -Alive..Content-
54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f       Type: applicatio
6e 2f 6a 61 76 61 73 63 72 69 70 74 0d 0a 0d 0a       n/javascript....
23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23       ################
23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23       ################
23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23       ################
23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23       ################
23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23       ################
23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23       ################
23 23 23 23 00 00 00 00 00 00 00 00 00 00 00 00       ####............
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00       ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00       ................
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00       ................
00 00 00 00 

