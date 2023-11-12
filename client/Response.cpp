#include <iostream>

#include "Response.h"
#include "Request.h"
#include "Utils.h"

Response::Response(SOCKET client_socket) {
	this->sock = client_socket;
}

std::string read_user_id(SOCKET client_socket) {
	// convert the 16 byte integer to a 32-char hex
	unsigned long long lower_bytes = 0;
	unsigned long long higher_bytes = 0;

	recv(client_socket, (char*)&lower_bytes, 8, 0);
	recv(client_socket, (char*)&higher_bytes, 8, 0);

	char* lower_hexis = (char*)malloc((16 + 1) * sizeof(char));
	char* higher_hexis = (char*)malloc((16 + 1) * sizeof(char));

	// convert to hex
	snprintf(lower_hexis, 16 + 1, "%llx", lower_bytes);
	snprintf(higher_hexis, 16 + 1, "%llx", higher_bytes);

	std::string uuid_hex = "";
	uuid_hex += higher_hexis;
	uuid_hex += lower_hexis;

	return uuid_hex;
}

void Response::read_header() {
	// read server version from header
	recv(this->sock, (char*)&this->server_version, 1, 0);

	// read response code from header
	recv(this->sock, (char*)&this->code, 2, 0);

	// read payload_size from header
	recv(this->sock, (char*)&this->payload_size, 4, 0);
}

// handle response code 2103
bool Response::handle_crc_validation(FileTransfer* file, Request* reqManager) {
	// std::cout << "in handle_crc_validation, this->uuid=" << reqManager->get_client_id() << std::endl;
	int content_size = 0; // size of file after encryption
	recv(this->sock, (char*)&content_size, 4, 0);

	// std::cout << "in handle_crc_validation, content_size=" << content_size << std::endl;

	char* filename = (char*)malloc(255 * sizeof(char));
	memset(filename, 0, 255);
	recv(this->sock, filename, 255, 0);

	unsigned long checksum = 0;
	recv(this->sock, (char*)&checksum, 4, 0);

	std::string filename_str(filename);

	if (this->crc_cycles_count == MAX_CRC_CYCLE_CALLS) {
		// send 1031, could not send valid CRC <MAX_CRC_CYCLE_CALLS> times, give up
		reqManager->final_invalid_crc_request(filename_str);

		this->read_header();
		this->handle_payload(file, reqManager);

		return false;
	}

	if (file->compare_checksum(checksum)) {
		// send 1029, success
		reqManager->valid_crc_request(filename_str);

		this->read_header();
		this->handle_payload(file, reqManager); // should receive 2104

		return true;
	}
	else {
		// send 1030, invalid crc
		reqManager->invalid_crc_request(filename_str);

		this->read_header();
		this->handle_payload(file, reqManager); // should receive 2104

		// send 1028, uploading file again
		reqManager->send_file_request(filename_str, file->get_encrypted_filecontent());
		
		this->read_header();
		this->handle_payload(file, reqManager); // should receive 2104
	}

	return false;
}

void Response::handle_payload(FileTransfer* file, Request* reqManager) {
	std::cout << "Got response:" << std::endl;
	std::cout << "\tserver_version: " << this->server_version << std::endl;
	std::cout << "\tcode: " << this->code << std::endl;
	std::cout << "\tpayload size: " << this->payload_size << std::endl;

	if (this->code != 2101 && this->code != 2107) {
		// requests 2101, 2107, do not any payload
		// so don't try to read user id from payload
		this->user_id = read_user_id(this->sock);
	}
	
	switch (this->code) {
	case 2100: {
		reqManager->set_client_id(this->user_id.c_str());
		break;
	}
	case 2101:
		err_n_die("User by that name already exists!");
		break;
	case 2102: {
		int key_length = this->payload_size - 16;
		char* encrypted_aes_key = (char*)malloc(key_length * sizeof(char));
		memset(encrypted_aes_key, 0, key_length);
		recv(this->sock, encrypted_aes_key, key_length, 0);

		// decrypt encrypted_aes_key with private key of RSA
		std::string encrypted_aes_key_str = std::string(encrypted_aes_key, key_length);
		file->set_aes_key(encrypted_aes_key_str);
		break;
	}
	case 2103: {
		this->crc_cycles_count++;

		bool is_successful_upload = this->handle_crc_validation(file, reqManager);
		if (is_successful_upload) {
			this->crc_cycles_count = 0;
			std::cout << "[SUCCESS] Confirmed CRC codes" << std::endl;
			return;
		}

		break;
	}
	case 2104: {
		break;
	}
	case 2105: {
		int key_length = this->payload_size - 16;
		char* encrypted_aes_key = (char*)malloc(key_length * sizeof(char));
		memset(encrypted_aes_key, 0, key_length);
		recv(this->sock, encrypted_aes_key, key_length, 0);

		std::string encrypted_aes_key_str = std::string(encrypted_aes_key, key_length);

		// decrypt encrypted_aes_key with private key of RSA
		file->set_aes_key(encrypted_aes_key_str);
		break;
	}
	case 2106: {
		this->relogin_req_failed = true;
		break;
	}
	case 2107:
		err_n_die("Server responded with an error, exiting..");
		break;
	default:
		err_n_die("Server responded with an unknown code, exiting..");
		break;
	}
}

bool Response::is_relogin_req_failed() { return this->relogin_req_failed; }
