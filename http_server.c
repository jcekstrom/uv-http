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
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "libuv/include/uv.h"
#include "http-parser/http_parser.h"
#include "http_server.h"

#define CHECK(r, loop, msg) \
    if (r) { \
        uv_err_t err = uv_last_error(loop); \
        fprintf(stderr, "%s: %s\n", msg, uv_strerror(err)); \
    }
#define UVERR(err, msg) fprintf(stderr, "%s: %s\n", msg, uv_strerror(err))
#define LOG(msg) puts(msg);
#define LOGF(fmt, params...) printf(fmt "\n", params);
#define LOG_ERROR(msg) puts(msg);

#define HTTP_RESPONSE_HEADERS \
    "HTTP/1.1 %d %s\r\n" \
    "Content-Type: %s\r\n" \
    "Content-Length: %d\r\n" \
    "%s\r\n"


// HTTP Parser Funcs
int on_message_begin(http_parser*);
int on_url(http_parser*, const char *at, size_t length);
int on_header_field(http_parser*, const char *at, size_t length);
int on_header_value(http_parser*, const char *at, size_t length);
int on_headers_complete(http_parser*);
int on_body(http_parser*, const char *at, size_t length);
int on_message_complete(http_parser*);

// HTTP Server Funcs
void on_close(uv_handle_t* handle);
void after_write(uv_write_t* req, int status);
void on_read(uv_stream_t* tcp, ssize_t nread, uv_buf_t buf);
void on_connect(uv_stream_t* server_handle, int status);


/*****************************************************************************
 * HTTP Callback Parser Functions
 ****************************************************************************/

int on_message_begin(http_parser* parser) {
    http_request_t* req = (http_request_t*) parser->data;
    LOGF("[ %5d ] on_message_begin", req->request_num);

    return 0;
}


int on_url(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = (http_request_t*) parser->data;
    LOGF("[ %5d ] on_url %s", req->request_num, at);

    // Parse URL and determine the handler

    return 0;
}


int on_header_field(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = (http_request_t*) parser->data;
    LOGF("[ %5d ] on_header_field %s", req->request_num, at);

    return 0;
}


int on_header_value(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = (http_request_t*) parser->data;
    LOGF("[ %5d ] on_header_value", req->request_num, at);

    return 0;
}


int on_headers_complete(http_parser* parser) {
    http_request_t* req = (http_request_t*) parser->data;
    int rv = 0;

    LOGF("[ %5d ] on_headers_complete", req->request_num);

    switch (parser->method) {
        case HTTP_GET:
            // we have everything to process the GET
            rv = 1; // Tell http_parser to just parse the rest, there is no body
            if (req->handler != NULL && req->handler(req)) {
                // Handle an error here
            }
            break;

        case HTTP_POST:
        case HTTP_PUT:
        case HTTP_HEAD:
        case HTTP_DELETE:
            
        default:
            // RETURN A 5XX message saying we don't support the method
            break;
    }



    /*
    uv_write(
            &req->write_req,
            (uv_stream_t*)&req->handle,
            &resbuf,
            1,
            after_write);
    */
    return 1;
}


int on_body(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = (http_request_t*) parser->data;

    LOGF("[ %5d ] on_body %s", req->request_num, at);

    return 0;
}


int on_message_complete(http_parser* parser) {
    http_request_t* req = (http_request_t*) parser->data;

    LOGF("[ %5d ] on_message_complete", req->request_num);

    return 0;
}


/*****************************************************************************
 * HTTP Server Callback Functions
 ****************************************************************************/
 
// TODO Pool this memory
uv_buf_t on_alloc(uv_handle_t* req, size_t suggested_size) {
    uv_buf_t buf;
    buf.base = malloc(suggested_size);
    buf.len = suggested_size;
    return buf;
}


void on_read(uv_stream_t* tcp, ssize_t nread, uv_buf_t buf) {
    size_t parsed;
    http_request_t *req = (http_request_t*)tcp->data;

    if (nread >= 0) {
        parsed = http_parser_execute(
                &req->parser, &req->server->parser_settings, buf.base, nread);
        if (parsed < nread) {
            LOG_ERROR("parse error");
            uv_close((uv_handle_t*) &req->handle, on_close);
        }
    } else {
        uv_err_t err = uv_last_error(req->server->uv_loop);
        if (err.code != UV_EOF) {
            UVERR(err, "read");
        }
    }

    free(buf.base);
}


void on_connect(uv_stream_t* server_handle, int status) {
    int r;
    http_request_t* req = malloc(sizeof(http_request_t));
    http_server_t *server = (http_server_t*)server_handle->data;

    // Setup the Request
    req->server = server;
    req->request_num = server->request_num;
    LOGF("[ %5d ] new connection", server->request_num++);

    uv_tcp_init(server->uv_loop, &req->handle);
    http_parser_init(&req->parser, HTTP_REQUEST);

    req->parser.data = req;
    req->handle.data = req;

    r = uv_accept(server_handle, (uv_stream_t*)&req->handle);
    CHECK(r, server->uv_loop, "accept");

    uv_read_start((uv_stream_t*)&req->handle, on_alloc, on_read);
}


void on_close(uv_handle_t* handle) {
    http_request_t* req = (http_request_t*) handle->data;

    LOGF("[ %5d ] connection closed", req->request_num);

    free(req);
}


void after_write(uv_write_t* req, int status) {
    uv_close((uv_handle_t*)req->handle, on_close);
}


int http_server_create(char *listen_addr, short port) {
    int r;

    http_server_t *server = malloc(sizeof(http_server_t)); 
    
    // Init the handler list
    server->handlers = NULL;

    // Initialize the parser
    http_parser_settings *parser = &server->parser_settings;
    // Setup the handlers
    parser->on_message_begin    = on_message_begin;
    parser->on_url              = on_url;
    parser->on_header_field     = on_header_field;
    parser->on_header_value     = on_header_value;
    parser->on_headers_complete = on_headers_complete;
    parser->on_message_complete = on_message_complete;

    // Create an event loop
    server->uv_loop = uv_default_loop();
    // Init a TCP "Server"
    r = uv_tcp_init(server->uv_loop, &server->tcp);
    CHECK(r, server->uv_loop, "bind");

    // Bind to the right addres/port
    struct sockaddr_in address = uv_ip4_addr(listen_addr, port);
    r = uv_tcp_bind(&server->tcp, address);
    CHECK(r, server->uv_loop, "bind");

    return 0;
}


int http_server_delete(http_server_t *server) {
    // Delete all the handlers...
    http_reqest_handler_def_t *curr_handler = server->handlers;
    while (curr_handler) {
        http_reqest_handler_def_t *next = curr_handler;
        // TODO delete pattern?
        free(curr_handler);
        curr_handler = next;
    }
    return 0;
    
}


int http_server_write_response(http_request_t *req, int status, const char *extra_headers, const char *content, const char *content_type, const uint32_t content_length) {
    uv_buf_t b;
    char buffer[1024];
    // Start
    b.base = buffer;
    b.len = snprintf(buffer, 1024, HTTP_RESPONSE_HEADERS, status, "OK" /*http_status_strings[status]*/, content_type, content_length, extra_headers);
    uv_write(&req->write_req, (uv_stream_t*)&req->handle, &b, 1, NULL); // last arg is a callback function here

    b.base = content;
    b.len = content_length;
    uv_write(&req->write_req, (uv_stream_t*)&req->handle, &b, 1, NULL); // last arg is a callback function here

    return 0; // TODO what should I return here?
}


int http_server_add_handler(http_server_t *server, const char *pattern, http_request_handler_func handler) {
    const char *error;
    int error_offset;
    // setup the last_handler to start
    http_reqest_handler_def_t *last = server->handlers;
    http_reqest_handler_def_t *new_handler = malloc(sizeof(http_reqest_handler_def_t));
    new_handler->pattern = pcre_compile(pattern, 0, &error, &error_offset, NULL);
    new_handler->handler = handler;
    // Add to the handlers list
    if (last) {
        while (last->next)
            // find the last one in the list
            last = last->next;
        last->next = new_handler;
    } else {
        server->handlers = new_handler;
    }

    return 0;
}

int http_server_run(http_server_t *server) {
    int r;

    uv_listen((uv_stream_t*)&server->tcp, 128, on_connect);

    LOG("listening on port");

    uv_run(server->uv_loop);
    return 0;
}


int http_server_stop(http_server_t *server) {
    // TODO Figure out if this is right??? I have no idea if I need to 
    uv_loop_delete(server->uv_loop);
    return 0;
}

