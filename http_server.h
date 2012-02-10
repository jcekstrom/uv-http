/* 
 * Copyright Ryati, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <pcre.h>
#include "libuv/include/uv.h"
#include "http-parser/http_parser.h"

// Define some event loop globals for now
// TODO Make these part of a struct???
enum header_type {
    HEADER_RANGE = 1,
    HEADER_CONTENT_TYPE
};

typedef struct http_request_s http_request_t;
typedef struct http_reqest_handler_def_s http_reqest_handler_def_t;
typedef struct http_server_s http_server_t;

typedef int (*http_request_handler_func) (http_request_t *req);

// Client Connection Struct


struct http_reqest_handler_def_s {
    pcre *pattern;
    http_request_handler_func *handler; 
    http_reqest_handler_def_t *next;
};


struct http_server_s {
    uv_loop_t* uv_loop;
    uv_tcp_t tcp;
    http_parser_settings parser_settings;
    uint32_t request_num;
    
    http_reqest_handler_def_t *handlers;
};


struct http_request_s {
    http_server_t *server;
    uv_tcp_t handle;
    http_parser parser;
    uv_write_t write_req;
    uint32_t request_num;

    uint8_t current_header;

    http_request_handler_func handler;

    uint32_t range_start;
    uint32_t range_end;
};

