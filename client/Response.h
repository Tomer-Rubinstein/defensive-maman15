#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")

#include "FileTransfer.h"
#include "Request.h"

class Response {
private:
	bool relogin_req_failed = false;
	std::string user_id;
	unsigned int server_version=0;
	unsigned int code=0;
	unsigned int payload_size=0;
	int crc_cycles_count=0;
	SOCKET sock;

	bool handle_crc_validation(FileTransfer* file, Request* reqManager);
public:

	Response(SOCKET client_socket);
	void handle_payload(FileTransfer* file, Request* reqManager);
	void read_header();

	bool is_relogin_req_failed();
};
