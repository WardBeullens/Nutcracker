CC=gcc

CFLAGS=
LFLAGS=-lcrypto -lpthread

IMPLEMENTATION_SOURCE = *.c
IMPLEMENTATION_HEADERS= *.h 

main: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS)
	gcc -o main $(IMPLEMENTATION_SOURCE) $(CFLAGS) $(LFLAGS) -g -lcrypto -O2 

.PHONY: clean
clean:
	rm -f test PQCgenKAT_sign  profile profile.txt fast *.req *.rsp >/dev/null