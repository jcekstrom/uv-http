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
#ifndef HTTP_SERVER_H_INCLUDED
#define HTTP_SERVER_H_INCLUDED

#include <inttypes.h>


// Define some event loop globals for now
// TODO Make these part of a struct???
enum header_type {
    HEADER_RANGE = 1,
    HEADER_CONTENT_TYPE
};

typedef struct http_request_s http_request_t;
typedef struct http_reqest_handler_def_s http_reqest_handler_def_t;
typedef struct http_client_s http_client_t;
typedef struct http_server_s http_server_t;

typedef int (*http_request_handler_func) (http_request_t *req);


http_server_t * http_server_create(char *listen_addr, short port);

int http_server_delete(http_server_t *server);

int http_server_add_handler(http_server_t *server, const char *pattern, http_request_handler_func handler);

int http_server_run(http_server_t *server);

int http_server_stop(http_server_t *server);

int http_request_write_response(http_request_t *req, int status, const char *extra_headers, 
        const char *content_type, const char *content, const uint32_t content_length);

int http_request_chunked_response_start(http_request_t *req, int status, const char *extra_headers);

int http_request_chunked_response_write(http_request_t *req, const char *data, int length);

int http_request_chunked_response_end(http_request_t *req);



#endif //HTTP_SERVER_H_INCLUDED
