#include <sstream>

#include "Request.h"
#include "Response.h"
#include "Utils.h"
#pragma pack(1)

#define HEADER_SIZE 1 + 2 + 4

Request::Request(SOCKET sock) {
	this->sock = sock;
	this->client_id = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
}

void Request::set_client_id(const char* client_id) {
	this->client_id = (const char*) malloc((32+1) * sizeof(char));
	memset((char*)this->client_id, 0, 32+1);
	memcpy((char*)this->client_id, client_id, 32);
}

void Request::send_header(int code, int payload_size) {
	RequestHeader req_header = {
		this->CLIENT_VERSION,
		code,
		payload_size
	};

	// since client_id is the first 16 bytes of the header,
	// send it as 2 seperated 8-byte packets
	std::string uuid(this->client_id);
	if (uuid.length() == 0) {
		// uuid is null bytes, happens in registration request
		// where the uuid is not needed.
		// send 16 null bytes as the uuid in response.
		char* null_bytes = (char*)malloc(16 * sizeof(char));
		memset((char*)null_bytes, 0, 16);
		send(this->sock, null_bytes, 16, 0);
	} else {
		// send lower
		std::stringstream ss1;
		std::string lower = uuid.substr(16, 16);
		unsigned long long lower_int;
		ss1 << std::hex << lower;
		ss1 >> lower_int;

		// send higher
		std::stringstream ss2;
		std::string higher = uuid.substr(0, 16);
		unsigned long long higher_int;
		ss2 << std::hex << higher;
		ss2 >> higher_int;

		struct uuid {
			unsigned long long lower_int;
			unsigned long long higher_int;
		};

		struct uuid user_id = { 0 };
		user_id.lower_int = lower_int;
		user_id.higher_int = higher_int;

		send(this->sock, (char*)&user_id, 16, 0);
	}

	// send the rest of the header
	send(this->sock, (char*)&req_header, HEADER_SIZE, 0);
}

void Request::register_request(std::string username) {
	NameOnlyPayload req_payload = { 0 };

	if (username.length() > 255) {
		err_n_die("username too long!");
	}
	memcpy(req_payload.username, username.c_str(), username.length());
	
	// send header: code=1025, payload_size=255
	this->send_header(REGISTER_REQ_CODE, USERNAME_PAYLOAD_SIZE);

	// send payload
	send(this->sock, (char*)&req_payload, USERNAME_PAYLOAD_SIZE, 0);
	std::cout << "sent payload with name " << req_payload.username << std::endl;
}

void Request::public_key_request(std::string username, std::string public_key) {
	NameKeyPayload req_payload = { 0 };
	
	if (username.length() > 255 || public_key.length() > 160) {
		err_n_die("username or public key too long!");
	}

	memcpy(req_payload.username, username.c_str(), username.length());
	memcpy(req_payload.public_key, public_key.c_str(), public_key.length());

	// send header: code=1025, payload_size=255
	this->send_header(SEND_PUBKEY_REQ_CODE, PUBKEY_PAYLOAD_SIZE);

	// send payload
	send(this->sock, (char*)&req_payload, PUBKEY_PAYLOAD_SIZE, 0);
}

void Request::send_file_request(std::string filename, std::string filecontent) {
	/*
	to send an upload file request, we need to send 3 packets:
		- first packet: Default request header (client_id, version, code, payload_size)
			where payload_size = size(<second packet>).
		- second packet: Constant "header" bytes of request code 1028 (content_size, filename)
			where content_size = size(<third packet>).
		- third packet: File content.
	*/

	FileContentPayloadHeader req_payload_header = { 0 };

	if (filename.length() > 255) {
		err_n_die("file name too long!");
	}

	req_payload_header.content_size = filecontent.length();
	memcpy(req_payload_header.filename, filename.c_str(), filename.length());

	std::cout << "[DEBUG] content_size: " << req_payload_header.content_size << std::endl;
	std::cout << "[DEBUG] filename: " << req_payload_header.filename << std::endl;

	// send header: code=1028, payload_size=255+4
	this->send_header(SEND_FILE_REQ_CODE, FILENAME_PAYLOAD_SIZE+4);

	// send payload header (filecontent_size[4 bytes] + filename[255 bytes])
	send(this->sock, (char*)&req_payload_header, FILENAME_PAYLOAD_SIZE+4, 0);

	// send payload (filecontent)
	send(this->sock, filecontent.c_str(), filecontent.length(), 0);
}

void Request::valid_crc_request(std::string filename) {
	FilenameOnlyPayload req_payload = { 0 };

	if (filename.length() > 255) {
		err_n_die("file name too long!");
	}

	memcpy(req_payload.filename, filename.c_str(), filename.length());

	this->send_header(VALID_CRC_REQ_CODE, FILENAME_PAYLOAD_SIZE);

	send(this->sock, (char*)&req_payload, FILENAME_PAYLOAD_SIZE, 0);
}

// after this method is invoked, a 1028 request should be sent again.
void Request::invalid_crc_request(std::string filename) {
	FilenameOnlyPayload req_payload = { 0 };

	if (filename.length() > 255) {
		err_n_die("file name too long!");
	}

	memcpy(req_payload.filename, filename.c_str(), filename.length());

	this->send_header(INVALID_CRC_REQ_CODE, FILENAME_PAYLOAD_SIZE);

	send(this->sock, (char*)&req_payload, FILENAME_PAYLOAD_SIZE, 0);
}

void Request::final_invalid_crc_request(std::string filename) {
	FilenameOnlyPayload req_payload = { 0 };

	if (filename.length() > 255) {
		err_n_die("file name too long!");
	}

	memcpy(req_payload.filename, filename.c_str(), filename.length());

	this->send_header(FINAL_INVALID_CRC_REQ_CODE, FILENAME_PAYLOAD_SIZE);

	send(this->sock, (char*)&req_payload, FILENAME_PAYLOAD_SIZE, 0);
}

void Request::relogin_request(std::string username) {
	NameOnlyPayload req_payload = { 0 };

	if (username.length() > 255) {
		err_n_die("Username too long!");
	}

	memcpy(req_payload.username, username.c_str(), username.length());

	this->send_header(RELOGIN_REQ_CODE, USERNAME_PAYLOAD_SIZE);

	send(this->sock, (char*)&req_payload, USERNAME_PAYLOAD_SIZE, 0);
}

const char* Request::get_client_id() { return this->client_id; }
