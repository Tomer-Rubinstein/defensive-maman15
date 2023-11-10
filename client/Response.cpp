#include <iostream>

#include "Response.h"
#include "Request.h"
#include "Utils.h"

Response::Response(SOCKET client_socket) {
	this->sock = client_socket;
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
	char* user_id = (char*)malloc(16 * sizeof(char));
	memset(user_id, 0, 16);
	recv(this->sock, user_id, 16, 0);

	int content_size = 0; // size of file after encryption
	recv(this->sock, (char*)&content_size, 4, 0);

	char* filename = (char*)malloc(255 * sizeof(char));
	memset(filename, 0, 255);
	recv(this->sock, filename, 255, 0);

	unsigned long checksum = 0;
	recv(this->sock, (char*)&checksum, 4, 0);

	std::string filename_str(filename);

	if (this->crc_cycles_count == MAX_CRC_CYCLE_CALLS) {
		// send 1031, could not send valid CRC <MAX_CRC_CYCLE_CALLS> times, give up
		reqManager->final_invalid_crc_request(filename_str);
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
	std::cout << "code: " << this->code << std::endl;

	switch (this->code) {
	case 2100: {
		char* user_id = (char*)malloc(16 * sizeof(char));
		recv(this->sock, user_id, 16, 0);

		reqManager->set_client_id(user_id);
		break;
	}
	case 2101: break;
	case 2102: {
		char* user_id = (char*)malloc(16 * sizeof(char));
		memset(user_id, 0, 16);
		recv(this->sock, user_id, 16, 0);

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
		char* user_id = (char*)malloc(16 * sizeof(char));
		memset(user_id, 0, 16);
		recv(this->sock, user_id, 16, 0);
		break;
	}
	case 2105: {
		char* user_id = (char*)malloc(17 * sizeof(char));
		memset(user_id, 0, 17);
		recv(this->sock, user_id, 16, 0);

		std::cout << "bruh user id is: " << user_id << std::endl;

		int key_length = this->payload_size - 16;
		char* encrypted_aes_key = (char*)malloc(key_length * sizeof(char));
		memset(encrypted_aes_key, 0, key_length);
		recv(this->sock, encrypted_aes_key, key_length, 0);

		std::cout << "lil blud wtf: " << encrypted_aes_key << std::endl;

		std::string encrypted_aes_key_str = std::string(encrypted_aes_key, key_length);

		std::cout << "key-length: " << key_length << std::endl;
		std::cout << "encrypted_aes_key base64 " << encrypted_aes_key_str << std::endl;

		// decrypt encrypted_aes_key with private key of RSA
		file->set_aes_key(encrypted_aes_key_str);
		break;
	}
	case 2106: {
		char* user_id = (char*)malloc(16 * sizeof(char));
		memset(user_id, 0, 16);
		recv(this->sock, user_id, 16, 0);

		this->relogin_req_failed = true;
		break;
	}
	case 2107:
		err_n_die("Server responded with an error, exiting..");
		break;
	default: break;
	}
}

bool Response::is_relogin_req_failed() { return this->relogin_req_failed; }
