// systemtap compile-server web api server header 
// Copyright (C) 2017-2020 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#ifndef __SERVER_H__
#define __SERVER_H__

#include <tuple>
#include <vector>
#include <string>
#include <mutex>
#include <map>
#include <condition_variable>

extern "C"
{
#include <microhttpd.h>
}

#if MHD_VERSION >= 0x00097002
// libmicrohttpd 0.9.71 broke API
#define MHD_RESULT enum MHD_Result
#else
#define MHD_RESULT int
#endif
  
using namespace std;

struct response
{
    unsigned int status_code;
    map<string, string> headers;
    string file;
    string content;
    string content_type;

    response(const unsigned int code,
	     const string &type = "text/html; charset=UTF-8") :
	status_code(code), content_type(type)
    {
    }
};

extern response get_404_response();

typedef map<string, vector<string>> post_params_t;

struct request
{
    post_params_t params;
    string base_dir;
    map<string, vector<string>> files;
    vector<string> matches;
#if 0
    request_headers headers;
    std::string body;
#endif
};

struct request_handler
{
    string name;
    virtual response GET(const request &req);
    virtual response PUT(const request &req);
    virtual response POST(const request &req);
    virtual response DELETE(const request &req);

    request_handler(string n) : name(n) {}
};

class server
{
public:
    void start();
    void wait();
    void stop();

    server(uint16_t port, std::string &cert_db_path);

    ~server()
    {
	stop();
    }

    void add_request_handler(const string &url_path_re,
			     request_handler &handler);
    const std::string & get_cert_db_path() const { return cert_db_path; }

private:
    condition_variable running_cv;
    mutex srv_mutex;
    uint16_t port;
    struct MHD_Daemon *dmn_ipv4;
    // FIXME: IPv6 support needed
    std::string cert_db_path;

    // FIXME: should this be a map?
    vector<tuple<string, request_handler *>> request_handlers;

    static MHD_RESULT access_handler_shim(void *cls,
				   struct MHD_Connection *connection,
				   const char *url,
				   const char *method,
				   const char *version,
				   const char *upload_data,
				   size_t *upload_data_size,
				   void **con_cls);

    MHD_RESULT access_handler(struct MHD_Connection *connection,
		       const char *url,
		       const char *method,
		       const char *version,
		       const char *upload_data,
		       size_t *upload_data_size,
		       void **con_cls);

    static void
	request_completed_handler_shim(void *cls,
				       struct MHD_Connection *connection,
				       void **con_cls,
				       enum MHD_RequestTerminationCode toe);

    void request_completed_handler(struct MHD_Connection *connection,
				   void **con_cls,
				   enum MHD_RequestTerminationCode toe);

    MHD_RESULT queue_response(const response &response, MHD_Connection *connection);
};

#endif /* __SERVER_H__ */
