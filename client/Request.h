#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define REGISTER_REQ_CODE 1025
#define SEND_PUBKEY_REQ_CODE 1026
#define RELOGIN_REQ_CODE 1027
#define SEND_FILE_REQ_CODE 1028
#define VALID_CRC_REQ_CODE 1029
#define INVALID_CRC_REQ_CODE 1030
#define FINAL_INVALID_CRC_REQ_CODE 1031

#define USERNAME_PAYLOAD_SIZE 255
#define PUBKEY_PAYLOAD_SIZE 160+USERNAME_PAYLOAD_SIZE
#define FILENAME_PAYLOAD_SIZE 255

#define MAX_CRC_CYCLE_CALLS 3

#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma pack(1)

#include <string>


struct RequestHeader {
	unsigned char version;
	unsigned short code;
	unsigned int payload_size;
};


// requests 1025, 1027
struct NameOnlyPayload {
	char username[255] = { 0 };
};

// requests 1029, 1030, 1031
struct FilenameOnlyPayload {
	char filename[255] = { 0 };
};

// request 1026
struct NameKeyPayload {
	char username[255] = { 0 };
	char public_key[160] = { 0 };
};

// request 1028
struct FileContentPayloadHeader {
	int content_size; // 4 bytes
	char filename[255] = { 0 };
};


class Request {
private:
	const char* client_id;
	SOCKET sock;
public:
	const static int CLIENT_VERSION = 3;

	Request(SOCKET sock);

	void set_client_id(const char* client_id);

	void register_request(std::string username);
	void relogin_request(std::string username);
	void public_key_request(std::string username, std::string public_key);
	void send_file_request(std::string filename, std::string filecontent);
	void valid_crc_request(std::string filename);
	void invalid_crc_request(std::string filename);
	void final_invalid_crc_request(std::string filename);
	void send_header(int code, int payload_size);

	const char* get_client_id();
};
