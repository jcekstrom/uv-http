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

#include "http_server.h"

#include <uv.h>
#include <http_parser.h>
#include <pcre.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>



struct http_reqest_handler_def_s {
    pcre *pattern;
    http_request_handler_func handler; 
    http_reqest_handler_def_t *next;
};


struct http_server_s {
    uv_loop_t* uv_loop;
    uv_tcp_t tcp;
    http_parser_settings parser_settings;
    uint32_t request_num;
    
    http_reqest_handler_def_t *handlers;
};


struct http_client_s {
    http_server_t *server;
    uv_tcp_t handle;
    uv_write_t write_req;
    // HTTP Parser...
    http_parser parser;

    http_request_t *request;
};


struct http_request_s {
    // HTTP Client - could service multiple requests...
    http_client_t *client;

    // Current Requestion number
    uint32_t request_num;
    // Used during parsing to determine what header
    // we are getting a value for
    uint8_t current_header;

    // Handler function to call based on the url/handler_def->pattern
    http_request_handler_func handler;
    // Args extracted using handler_def pattern
    const char **pattern_args;

    // Used for Range Requests
    uint32_t range_start;
    uint32_t range_end;
};



#define CHECK(r, loop, msg) \
    if (r) { \
        uv_err_t err = uv_last_error(loop); \
        fprintf(stderr, "%s: %s\n", msg, uv_strerror(err)); \
    }
#define UVERR(err, msg) fprintf(stderr, "%s: %s\n", msg, uv_strerror(err))
#define LOG(msg) puts(msg);
#define LOGF(fmt, params...) printf(fmt "\n", params);
#define LOG_ERROR(msg) puts(msg);

// HTTP Parser Funcs
int _http_cb_on_message_begin(http_parser*);
int _http_cb_on_url(http_parser*, const char *at, size_t length);
int _http_cb_on_header_field(http_parser*, const char *at, size_t length);
int _http_cb_on_header_value(http_parser*, const char *at, size_t length);
int _http_cb_on_headers_complete(http_parser*);
int _http_cb_on_body(http_parser*, const char *at, size_t length);
int _http_cb_on_message_complete(http_parser*);

// HTTP Server Funcs
static void _http_cb_on_close(uv_handle_t* handle);
static void _http_cb_write_req_done(uv_write_t* req, int status);
static void _http_cb_on_read(uv_stream_t* tcp, ssize_t nread, uv_buf_t buf);
static void _http_cb_on_connect(uv_stream_t* server_handle, int status);

// Request Functions
static http_request_t *_http_request_init(http_client_t *client);
static http_client_t *_http_client_init(uv_stream_t* server_handle);

// Client Functions

/*****************************************************************************
 * HTTP Callback Parser Functions
 ****************************************************************************/

int _http_cb_on_message_begin(http_parser* parser) {
    // Get Client from parser
    http_client_t* client = (http_client_t*) parser->data;
    // Create a request
    client->request = _http_request_init(client);
    
    LOGF("[ %5d ] _http_cb_on_message_begin", client->request->request_num);

    return 0;
}


int _http_cb_on_url(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = ((http_client_t*)parser->data)->request;
    http_server_t* server = req->client->server;
    LOGF("[ %5d ] _http_cb_on_url %s", req->request_num, at);
    

    // Parse URL and determine the handler
    int rc;
    int ovector[30];
    http_reqest_handler_def_t *hdef = server->handlers;
    while (hdef != NULL) {
        int count = pcre_exec(
                hdef->pattern,  /* result of pcre_compile() */
                NULL,           /* we didn't study the pattern */
                at,  /* the subject string */
                length,             /* the length of the subject string */
                0,              /* start at offset 0 in the subject */
                0,              /* default options */
                ovector,        /* vector of integers for substring information */
                30);            /* number of elements (NOT size in bytes) */

        // If the pattern matches...
        if (count >= 0) {
            // Get args out of pattern
            rc = pcre_get_substring_list(at, ovector, count, &req->pattern_args);
            req->handler = hdef->handler;
            break;
        }

        // Try the next handler
        hdef = hdef->next;
    }

    return 0;
}


int _http_cb_on_header_field(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = ((http_client_t*)parser->data)->request;
    LOGF("[ %5d ] _http_cb_on_header_field %s", req->request_num, at);
        
    switch (at[0]) {
        case 'R':
            if (length == 5) {
                // Assume "Range"
                req->current_header = HEADER_RANGE;
            }
            break;

        default:
            req->current_header = 0;
            break;
    }

    return 0;
}


int _http_cb_on_header_value(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = ((http_client_t*)parser->data)->request;
    char *dash = NULL;
    LOGF("[ %5d ] _http_cb_on_header_value %s", req->request_num, at);

    // Right now care about range requests
    switch (req->current_header) {
        case HEADER_RANGE:
            // null out -
            dash = memchr(at, length, '-');
            if (dash != NULL) {
                *dash = '\0';
                req->range_start = atol(at);
                if (++dash != NULL)
                    req->range_end = atol(dash);
            }
            break;

        default:
            break;
    }

    return 0;
}


int _http_cb_on_headers_complete(http_parser* parser) {
    http_request_t* req = ((http_client_t*)parser->data)->request;
    int rv = 0;

    LOGF("[ %5d ] _http_cb_on_headers_complete", req->request_num);

    switch (parser->method) {
        case HTTP_GET:
            // we have everything to process the GET
            rv = 1; // Tell http_parser to just parse the rest, there is no body
            if (req->handler != NULL) {
                int ret = req->handler(req);
                if (ret != 0) {
                    // Handle an error here
                }
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

    return rv;
}


int _http_cb_on_body(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = ((http_client_t*)parser->data)->request;

    LOGF("[ %5d ] _http_cb_on_body %s", req->request_num, at);

    return 0;
}


int _http_cb_on_message_complete(http_parser* parser) {
    http_request_t* req = ((http_client_t*)parser->data)->request;

    LOGF("[ %5d ] _http_cb_on_message_complete", req->request_num);

    return 0;
}


/*****************************************************************************
 * HTTP Server Callback Functions
 ****************************************************************************/
 
// TODO Pool this memory
uv_buf_t _http_cb_on_alloc(uv_handle_t* req, size_t suggested_size) {
    uv_buf_t buf;
    buf.base = malloc(suggested_size);
    buf.len = suggested_size;
    return buf;
}


static void _http_cb_on_read(uv_stream_t* tcp, ssize_t nread, uv_buf_t buf) {
    size_t parsed;
    // Get the client
    http_client_t *client = (http_client_t*)tcp->data;

    if (nread >= 0) {
        // Read Data for Client connection
        parsed = http_parser_execute(&client->parser, &client->server->parser_settings, buf.base, nread);
        if (parsed < nread) {
            // HTTP Parse Error
            LOG_ERROR("parse error");
            uv_close((uv_handle_t*) &client->handle, _http_cb_on_close);
        }
    } else {
        // No Data Read... Handle Error case
        uv_err_t err = uv_last_error(client->server->uv_loop);
        if (err.code != UV_EOF) {
            UVERR(err, "read");
        }
    }

    free(buf.base);
}


static void _http_cb_on_connect(uv_stream_t* server_handle, int status) {
    //LOGF("New Connection");
    // Create/Initialize a HTTP Client
    http_client_t *client = _http_client_init(server_handle);

    // Start reading oof the Client
    uv_read_start((uv_stream_t*)&client->handle, _http_cb_on_alloc, _http_cb_on_read);
}


static void _http_cb_on_close(uv_handle_t* handle) {
    http_request_t* req = (http_request_t*) handle->data;

    LOGF("[ %5d ] connection closed", req->request_num);

    free(req);
}


static void _http_cb_write_req_done(uv_write_t* req, int status) {
    uv_close((uv_handle_t*)req->handle, _http_cb_on_close);
}

static http_request_t *_http_request_init(http_client_t *client) {
    // Alloc req
    http_request_t *req = malloc(sizeof(http_request_t));
    // Setup Req
    req->client = client;
    req->request_num = ++client->server->request_num;

    return req;
}


static void _http_request_finish(http_request_t *req) {


}

static void _http_write_request_done_cb(uv_write_t* write_req, int status) {
    http_request_t* req = ((http_client_t*)write_req->data)->request;
    _http_request_finish(req);
}

static http_client_t *_http_client_init(uv_stream_t* server_handle) {
    int r;
    // Get the server
    http_server_t *server = (http_server_t*)server_handle->data;
    
    // Create Client
    http_client_t *client = malloc(sizeof(http_client_t));

    // Setup the Client
    client->server = server;
    client->request = NULL;
    // Initializing http parser for REQUST
    http_parser_init(&client->parser, HTTP_REQUEST);
    // Setup the parser data so we have access to the request
    client->parser.data = client;

    
    // Init UV stuff
    uv_tcp_init(server->uv_loop, &client->handle);
    r = uv_accept(server_handle, (uv_stream_t*)&client->handle);
    // TODO handle uv_accept ERROR
    
    // Set the handle's data so we can get our client in the read/write funcs
    client->handle.data = client;

    return client;
}

static void _http_client_delete(http_client_t *req) {


}


/*****************************************************************************
 * HTTP Server API
 ****************************************************************************/
http_server_t *http_server_create(char *listen_addr, short port) {
    int r;

    http_server_t *server = malloc(sizeof(http_server_t)); 
    
    // Init the handler list
    server->handlers = NULL;

    // Initialize the parser
    http_parser_settings *parser = &server->parser_settings;
    // Setup the handlers
    parser->on_message_begin    = _http_cb_on_message_begin;
    parser->on_url              = _http_cb_on_url;
    parser->on_header_field     = _http_cb_on_header_field;
    parser->on_header_value     = _http_cb_on_header_value;
    parser->on_headers_complete = _http_cb_on_headers_complete;
    parser->on_message_complete = _http_cb_on_message_complete;

    // Create an event loop
    server->uv_loop = uv_default_loop();
    // Init a TCP "Server"
    r = uv_tcp_init(server->uv_loop, &server->tcp);
    CHECK(r, server->uv_loop, "bind");
    server->tcp.data = server;

    // Bind to the right addres/port
    struct sockaddr_in address = uv_ip4_addr(listen_addr, port);
    r = uv_tcp_bind(&server->tcp, address);
    CHECK(r, server->uv_loop, "bind");

    return server;
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

    r = uv_listen((uv_stream_t*)&server->tcp, 128, _http_cb_on_connect);

    LOG("listening on port");

    r = uv_run(server->uv_loop);
    return 0;
}


int http_server_stop(http_server_t *server) {
    // TODO Figure out if this is right??? I have no idea if I need to 
    uv_loop_delete(server->uv_loop);
    return 0;
}


/*****************************************************************************
 * HTTP Server Response API
 ****************************************************************************/
 
#define HTTP_RESPONSE_HEADERS \
    "HTTP/1.1 %d %s\r\n" \
    "Content-Type: %s\r\n" \
    "Content-Length: %d\r\n" \
    "%s\r\n"

static inline
int _http_request_write(http_request_t *req, const char *data, int length, uv_write_cb callback) {
    uv_buf_t b;
    b.base = (char*)data;
    b.len = length;

    uv_write(&req->client->write_req, (uv_stream_t*)&req->client->handle, &b, 1, callback); // last arg is a callback function here

    return 0;
}

int http_request_write_response(http_request_t *req, int status, const char *extra_headers, 
        const char *content_type, const char *content, const uint32_t content_length) {
    char buffer[1024];
    int length = snprintf(buffer, 1024, HTTP_RESPONSE_HEADERS, status, "OK" /*http_status_strings[status]*/, content_type, content_length, extra_headers);
    // Write headers
    int ret = _http_request_write(req, buffer, length, NULL); 
    // write cotent
    ret = _http_request_write(req, content, content_length, _http_write_request_done_cb);
    return 0; // TODO what should I return here?
}


int http_request_chunked_response_start(http_request_t *req, int status, const char *extra_headers)
{
    return 0;
}


int http_request_chunked_response_write(http_request_t *req, const char *data, int length) {
    return 0;
}


int http_request_chunked_response_end(http_request_t *req) {
    return 0;
}

