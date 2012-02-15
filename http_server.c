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
    // HTTP Parser...
    http_parser parser;
    http_request_t *request;
    int close_connection;
};

    uv_write_t write_req;

typedef struct http_write_cb_s http_write_cb_t;
struct http_write_cb_s {
    // Callback info to free buffers
    http_write_cb cb;
    void *data;
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

#define RESPONSE_HEADER_SIZE 1024

// HTTP Parser Funcs
int _http_parser__on_message_begin(http_parser*);
int _http_parser__on_url(http_parser*, const char *at, size_t length);
int _http_parser__on_header_field(http_parser*, const char *at, size_t length);
int _http_parser__on_header_value(http_parser*, const char *at, size_t length);
int _http_parser__on_headers_complete(http_parser*);
int _http_parser__on_body(http_parser*, const char *at, size_t length);
int _http_parser__on_message_complete(http_parser*);

// HTTP Server Funcs
static void _http_uv__on_close__cb(uv_handle_t* handle);
static void _http_uv__on_read__cb(uv_stream_t* tcp, ssize_t nread, uv_buf_t buf);
static void _http_uv__on_connect__cb(uv_stream_t* server_handle, int status);

// Request Functions
static http_request_t *_http_request__init(http_client_t *client);
static void _http_request__finish(http_request_t *req);
static http_client_t *_http_client__init(uv_stream_t* server_handle);
static void _http_client__finish(http_client_t *req);

// Client Functions

/*****************************************************************************
 * HTTP Callback Parser Functions
 ****************************************************************************/

int _http_parser__on_message_begin(http_parser* parser) {
    // Get Client from parser
    http_client_t* client = (http_client_t*) parser->data;
    // Create a request
    client->request = _http_request__init(client);
    
    LOGF("[ %5d ] _http_parser__on_message_begin", client->request->request_num);

    return 0;
}


int _http_parser__on_url(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = ((http_client_t*)parser->data)->request;
    http_server_t* server = req->client->server;
    LOGF("[ %5d ] _http_parser__on_url %s", req->request_num, at);
    

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


int _http_parser__on_header_field(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = ((http_client_t*)parser->data)->request;
    LOGF("[ %5d ] _http_parser__on_header_field %s", req->request_num, at);
        
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


int _http_parser__on_header_value(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = ((http_client_t*)parser->data)->request;
    char *dash = NULL;
    LOGF("[ %5d ] _http_parser__on_header_value %s", req->request_num, at);

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


int _http_parser__on_headers_complete(http_parser* parser) {
    http_request_t* req = ((http_client_t*)parser->data)->request;

    LOGF("[ %5d ] _http_parser__on_headers_complete", req->request_num);

    return 0;
}


int _http_parser__on_body(http_parser* parser, const char *at, size_t length) {
    http_request_t* req = ((http_client_t*)parser->data)->request;

    LOGF("[ %5d ] _http_parser__on_body %s", req->request_num, at);

    return 0;
}


int _http_parser__on_message_complete(http_parser* parser) {
    int rv = 0;
    http_request_t* req = ((http_client_t*)parser->data)->request;
    LOGF("[ %5d ] _http_parser__on_message_complete", req->request_num);

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

    _http_request__finish(req);
    return 0;
}


/*****************************************************************************
 * HTTP Server Callback Functions
 ****************************************************************************/
 
// TODO Pool this memory
uv_buf_t _http_uv__on_alloc__cb(uv_handle_t* req, size_t suggested_size) {
    uv_buf_t buf;
    buf.base = malloc(suggested_size);
    buf.len = suggested_size;
    return buf;
}


static void _http_uv__on_read__cb(uv_stream_t* tcp, ssize_t nread, uv_buf_t buf) {
    size_t parsed;
    // Get the client
    http_client_t *client = (http_client_t*)tcp->data;

    if (nread >= 0) {
        // Read Data for Client connection
        parsed = http_parser_execute(&client->parser, &client->server->parser_settings, buf.base, nread);
        if (parsed < nread || http_should_keep_alive(&client->parser)) {
            // HTTP Parse Error
            LOG_ERROR("parse error");
            uv_close((uv_handle_t*) &client->handle, _http_uv__on_close__cb);
        }
    } else {
        // No Data Read... Handle Error case
        uv_err_t err = uv_last_error(client->server->uv_loop);
        if (err.code != UV_EOF) {
            UVERR(err, "read");
        }
    }

    // Free memory that was allocated by _http_uv__on_alloc__cb
    free(buf.base);
}


static void _http_uv__on_connect__cb(uv_stream_t* server_handle, int status) {
    //LOGF("New Connection");
    // Create/Initialize a HTTP Client
    http_client_t *client = _http_client__init(server_handle);

    // Start reading oof the Client
    uv_read_start((uv_stream_t*)&client->handle, _http_uv__on_alloc__cb, _http_uv__on_read__cb);
}


static void _http_uv__on_close__cb(uv_handle_t* handle) {
    //LOGF("[ %5d ] connection closed", client->request_num);
    _http_client__finish((http_client_t*) handle->data);
}


static http_request_t *_http_request__init(http_client_t *client) {
    // Alloc req
    http_request_t *req = malloc(sizeof(http_request_t));
    // Setup Req
    req->client = client;
    req->request_num = ++client->server->request_num;

    return req;
}


static void _http_request__finish(http_request_t *req) {
    // Check to see if http 1.1 and whether to keep connection open
    http_client_t *client = req->client;
    if (!http_should_keep_alive(&client->parser)) {
        client->close_connection = 1;
    }
    client->request = NULL;
    // Free up the Request obejct.
    free(req);
}

static http_client_t *_http_client__init(uv_stream_t* server_handle) {
    int r;
    // Get the server
    http_server_t *server = (http_server_t*)server_handle->data;
    
    // Create Client
    http_client_t *client = malloc(sizeof(http_client_t));

    // Setup the Client
    client->server = server;
    client->request = NULL;
    client->close_connection = 0;
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

static void _http_client__finish(http_client_t *client) {
    // TODO figure out uv_close and deletion of client / tcp connection
    if (client->request != NULL) {
        _http_request__finish(client->request);
    }
    // close the handle
    // Assume this is called by the close function, so don't close the handle
    // uv_close((uv_handle_t*) &client->handle, _http_uv__on_close__cb);
    // No need to free up the http_parser memory because it's all contained
    // in the client.
    // Free up the memory of the client
    free(client);
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
    parser->on_message_begin    = _http_parser__on_message_begin;
    parser->on_url              = _http_parser__on_url;
    parser->on_header_field     = _http_parser__on_header_field;
    parser->on_header_value     = _http_parser__on_header_value;
    parser->on_headers_complete = _http_parser__on_headers_complete;
    parser->on_message_complete = _http_parser__on_message_complete;

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

    r = uv_listen((uv_stream_t*)&server->tcp, 128, _http_uv__on_connect__cb);

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
#define http_connection_header_value(req) \
    (char*)(http_should_keep_alive(&(req)->client->parser) ? "close" : "keep-alive")

static void _http_request__write_callback(uv_write_t* write_req, int status) {
    // get the callback object, which is in front of the write_req
    http_write_cb_t *callback_obj = (http_write_cb_t*)(((uint8_t*)write_req) - sizeof(http_write_cb_t)); 
    // Call our callback
    if (callback_obj->cb != NULL) {
        callback_obj->cb(callback_obj->data);
    }
    // Free up the memory
    free(callback_obj);
}

static inline
int _http_request__write(http_request_t *req, uv_buf_t *buffers, int count, http_write_cb cb, void *cb_data) {
    // Malloc memory for our extra callback stuff and the uv_write_t
    http_write_cb_t *callback_obj = malloc(sizeof(http_write_cb_t) + sizeof(uv_write_t));

    // Setup our own special callback
    callback_obj->cb = cb;
    callback_obj->data = cb_data;

    // Do the write
    return uv_write(
            (uv_write_t*)(((uint8_t*)callback_obj) + sizeof(http_write_cb_t)), // uv_write_t ptr
            (uv_stream_t*)&req->client->handle, // handle to write to
            buffers, // uv_buf_t
            count, // # of buffers to write
            _http_request__write_callback
        ); 
}

#define HTTP_RESPONSE_HEADERS \
    "HTTP/1.1 %d %s\r\n" \
    "Connection: %s\r\n" \
    "Content-Type: %s\r\n" \
    "Content-Length: %d\r\n" \
    "%s\r\n"

int http_request_write_response_string(http_request_t *req, int status, const char *extra_headers, const char *content_type, const char *content, const uint32_t content_length, http_write_cb cb, void *cb_data) {
    uv_buf_t b;
    b.base = (char*)content;
    b.len = content_length;
    return http_request_write_response_buffers(req, status, extra_headers, content_type, &b, 1, cb, cb_data);
}


int http_request_write_response_buffers(http_request_t *req, int status, const char *extra_headers, const char *content_type, uv_buf_t *content_buffers, int content_buffers_count, http_write_cb cb, void *cb_data) {
    uv_buf_t header;
    char *headers_buffer = malloc(RESPONSE_HEADER_SIZE);
    int content_length = 0;
    int length;
    int i;

    for (i=0; i < content_buffers_count; i++) {
        content_length += content_buffers[i].len;
    }

    length = snprintf(
            headers_buffer,
            RESPONSE_HEADER_SIZE,
            HTTP_RESPONSE_HEADERS,
            status,
            http_status_code_text(status),
            http_connection_header_value(req),
            content_type,
            content_length,
            extra_headers);

    // Write headers
    header.base = headers_buffer;
    header.len = length;

    _http_request__write(req, &header, 1, free, headers_buffer); // Call free on the headers buffer
    _http_request__write(req, content_buffers, content_buffers_count, cb, cb_data); // Call callback sent for the content

    return 0; // TODO what should I return here?
}


#define HTTP_RESPONSE_HEADERS_CHUNKED \
    "HTTP/1.1 %d %s\r\n" \
    "Connection: %s\r\n" \
    "Content-Type: %s\r\n" \
    "Transfer-Encoding: chunked\r\n" \
    "%s\r\n"

int http_request_chunked_response_start(http_request_t *req, int status, const char *extra_headers, const char *content_type) {
    uv_buf_t header;
    char *headers_buffer = malloc(RESPONSE_HEADER_SIZE);
    int length = snprintf(
            headers_buffer,
            RESPONSE_HEADER_SIZE,
            HTTP_RESPONSE_HEADERS_CHUNKED,
            status,
            http_status_code_text(status),
            http_connection_header_value(req),
            content_type,
            extra_headers);

    // Write headers
    header.base = headers_buffer;
    header.len = length;

    _http_request__write(req, &header, 1, free, headers_buffer); // Call free on the headers buffer
    return 0;
}


int http_request_chunked_response_write(http_request_t *req, const char *data, int data_length, http_write_cb cb, void *cb_data) {
    return 0;
    uv_buf_t b;
    char *headers_buffer = malloc(32);
    int length = snprintf(headers_buffer, 32, "%X\r\n", length);

    // Write headers
    b.base = headers_buffer;
    b.len = length;
    _http_request__write(req, &b, 1, free, headers_buffer); // Call free on the headers buffer

    // write content
    b.base = (char*)data;
    b.len = data_length;
    _http_request__write(req, &b, 1, cb, cb_data); // Call free on the headers buffer
    return 0;
}


int http_request_chunked_response_end(http_request_t *req) {
    return 0;
}



/*****************************************************************************
 * HTTP Utility Functions
 ****************************************************************************/

const char* http_status_code_text(uint32_t status) {
    switch(status)
    {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
                  //case 306: return "(reserved)";
        case 307: return "Temporary Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request-URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        default: break;
    }
    return "UNKNOWN STATUS CODE";
}


