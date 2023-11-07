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

int main() {
	TransferInfo* transfer_info = new TransferInfo();
	FileTransfer* file = new FileTransfer(transfer_info->get_target_filepath());

	std::cout << "public key base64: " << file->get_pubkey_b64() << std::endl;
	std::cout << "private key base64: " << file->get_privkey_b64() << std::endl;

	SOCKET client_socket = connect_to_server(HOST, PORT);

	Request* req = new Request(client_socket);
	Response* resp = new Response(client_socket);

	// login or signup
	MeInfo* me_info = new MeInfo();
	PrivKeyFile* priv_key_file = new PrivKeyFile();
	if (me_info->read_file()) {
		// file exists, re-login request

		std::cout << "found existing uuid: " << me_info->get_uuid() << std::endl;
		std::cout << "found existing username: " << transfer_info->get_username() << std::endl;
		std::cout << "found existing private key: " << priv_key_file->get_b64_priv_key() << std::endl;

		// read user data from previous run
		std::string username = me_info->get_username();
		std::string uuid = me_info->get_uuid();

		req->set_client_id(uuid.c_str());
		file->import_private_key(priv_key_file->get_b64_priv_key());

		// i never set the aes key?
		// where is the "file->set_aes_key(encrypted_aes_key_str)"?

		req->relogin_request(username);

		resp->read_header();
		resp->handle_payload(file, req);
	}
	else {
		// file does not exist, register request

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
	
	// TODO
	// on re-login, sending encrypted file doesn't work.
	// on first signup, works perfectly fine.
	// maybe it's something with class members not set properly.

	std::string content = file->get_encrypted_filecontent();
	req->send_file_request(transfer_info->get_target_filepath(), content);

	resp->read_header();
	resp->handle_payload(file, req);

	
	/*
	char* client_id = (char*)malloc(16 * sizeof(char));
	memcpy(client_id, "hsQU2s3c8DNsis1I", 16);

	
	// if user not registered bla bla bla
	// req->register_request("tomer");

	req->public_key_request("tomer", Base64Wrapper::decode(file->get_pubkey_b64()));

	Response* resp = new Response(client_socket);

	resp->read_header();
	resp->handle_payload(file, req);

	std::string content = file->get_encrypted_filecontent();
	req->send_file_request("here.txt", content);

	resp->read_header();
	resp->handle_payload(file, req);
	*/

	// closesocket(client_socket);
	// WSACleanup();

	return 0;
}
