CC?=gcc
AR?=ar

CPPFLAGS += -I. -Ilibuv/include -Ihttp-parser/ -I/opt/local/include -L/opt/local/lib -lm -lpthread -lpcre
CPPFLAGS_DEBUG = $(CPPFLAGS) -DHTTP_PARSER_STRICT=1 -DHTTP_PARSER_DEBUG=1
CPPFLAGS_DEBUG += $(CPPFLAGS_DEBUG_EXTRA)
CPPFLAGS_FAST = $(CPPFLAGS) -DHTTP_PARSER_STRICT=0 -DHTTP_PARSER_DEBUG=0
CPPFLAGS_FAST += $(CPPFLAGS_FAST_EXTRA)

CFLAGS += -Wall
#CFLAGS += -Wall -Wextra -Werror
CFLAGS_DEBUG = $(CFLAGS) -O0 -g $(CFLAGS_DEBUG_EXTRA)
CFLAGS_FAST = $(CFLAGS) -O3 $(CFLAGS_FAST_EXTRA)

package: http_server.o test_server
	$(AR) rcs libuv_http.a http_server.o http-parser/http_parser.o

libuv/uv.a:
	$(MAKE) -C libuv

http-parser/http_parser.o:
	$(MAKE) -C http-parser http_parser.o

http_server.o: http_server.c http_server.h Makefile libuv/uv.a http-parser/http_parser.o \
	libuv/include/uv.h http-parser/http_parser.h 
	$(CC) $(CPPFLAGS_DEBUG) $(CFLAGS_DEBUG) -c http_server.c 


test_server: http_server.o http_server.c http_server.h Makefile libuv/uv.a http-parser/http_parser.o \
	libuv/include/uv.h http-parser/http_parser.h 
	$(CC) $(CPPFLAGS_DEBUG) $(CFLAGS_DEBUG) -o test_server test_server.c http_server.o libuv/uv.a http-parser/http_parser.o
	

clean:
	rm -f *.o *.a 

.PHONY: clean package test-run test-run-timed test-valgrind
