#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma pack(1)

#include <iostream>
#include <iomanip>
#include <inttypes.h>

#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "FileTransfer.h"
#include "Response.h"
#include "Request.h"
#include "TransferInfo.h"
#include "MeInfo.h"
#include "PrivKeyFile.h"

#define HOST "127.0.0.1"
#define PORT 8000

SOCKET connect_to_server(const char* host, int port) {
	WSAData wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(host);
	clientService.sin_port = htons(port);

	connect(client_socket, (struct sockaddr*)&clientService, sizeof(clientService));
	std::cout << "[SUCCESS] Connected to server" << std::endl;

	return client_socket;
}

void handle_register(MeInfo* me_info, PrivKeyFile* priv_key_file, Request* req, Response* resp, FileTransfer* file, TransferInfo* transfer_info) {
	// read username from transfer.info
	std::string username = transfer_info->get_username();
	req->register_request(username); // register request ignores client_id in header

	resp->read_header();
	resp->handle_payload(file, req); // sets field "client_id" of req to uuid returned from server

	// we now have username, client_id and priv_key. save them to "me.info"
	me_info->write_file(username, std::string(req->get_client_id()), file->get_privkey_b64());

	// save baset64 private key to priv.key file
	priv_key_file->write_b64_priv_key(file->get_privkey_b64());

	req->public_key_request(username, Base64Wrapper::decode(file->get_pubkey_b64()));

	resp->read_header();
	resp->handle_payload(file, req);
}

void handle_relogin(SOCKET client_socket, MeInfo** me_info, PrivKeyFile** priv_key_file, Request** req, Response** resp, FileTransfer** file, TransferInfo** transfer_info) {
	// read user data from previous run
	std::string username = (*me_info)->get_username();
	std::string uuid = (*me_info)->get_uuid();

	(*req)->set_client_id(uuid.c_str());
	(*file)->import_private_key((*priv_key_file)->get_b64_priv_key());

	(*req)->relogin_request(username);

	(*resp)->read_header();
	(*resp)->handle_payload(*file, *req);

	if ((*resp)->is_relogin_req_failed()) {
		std::cout << "[WARN] relogin request failed, registering new user.." << std::endl;
		*transfer_info = new TransferInfo();
		*me_info = new MeInfo();
		*priv_key_file = new PrivKeyFile();
		*file = new FileTransfer((*transfer_info)->get_target_filepath());
		*req = new Request(client_socket);
		*resp = new Response(client_socket);
		handle_register(*me_info, *priv_key_file, *req, *resp, *file, *transfer_info);
		return;
	}
}


int main() {
	TransferInfo* transfer_info = new TransferInfo();
	FileTransfer* file = new FileTransfer(transfer_info->get_target_filepath());

	std::cout << "public key base64: " << file->get_pubkey_b64() << std::endl;
	std::cout << "private key base64: " << file->get_privkey_b64() << std::endl;

	SOCKET client_socket = connect_to_server(HOST, PORT);

	Request* req = new Request(client_socket);
	Response* resp = new Response(client_socket);

	std::cout << "test" << std::endl;

	// login or signup
	MeInfo* me_info = new MeInfo();
	PrivKeyFile* priv_key_file = new PrivKeyFile();
	if (me_info->read_file()) {
		// file exists, re-login request
		handle_relogin(client_socket, &me_info, &priv_key_file, &req, &resp, &file, &transfer_info);
	}
	else {
		// file does not exist, register request
		handle_register(me_info, priv_key_file, req, resp, file, transfer_info);
	}

	std::string content = file->get_encrypted_filecontent();
	req->send_file_request(transfer_info->get_target_filepath(), content);

	resp->read_header();
	resp->handle_payload(file, req);

	closesocket(client_socket);
	WSACleanup();

	return 0;
}
