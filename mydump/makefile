HEADER = mydump.h

default: mydump

mydump.o: mydump.c $(HEADER)
	gcc -c mydump.c -lpcap -o mydump.o
	
mydump: mydump.o
	gcc mydump.o -lpcap -o mydump
	
clean:
	-rm -f mydump.o
	-rm -f mydump
