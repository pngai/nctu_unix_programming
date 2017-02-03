CC = gcc
CFLAGS = -g -Wall
.PHONY: clean test zip

TARGET= hijack.so

all: $(TARGET)

hijack.so: hijack.c
	$(CC) $(CFLAGS) -o $@ -shared -fPIC $^ -ldl

clean:
	rm -f hijack.so
	rm -f ./index.html*
	rm -f log.txt ssl_log.txt

test: hijack.so
	LD_PRELOAD=./hijack.so wget www.google.com

testssl: hijack.so
	LD_PRELOAD=./hijack.so wget  https://www.google.com

zip:
	zip hw2 README hijack.c Makefile
