#pragma once

#include "RSAWrapper.h"
#include "Base64Wrapper.h"

class FileTransfer {
private:
	std::string privkey_b64;
	std::string pubkey_b64;
	std::string filepath;
	std::string aes_key;
public:
	unsigned long checksum;
	
public:
	FileTransfer(std::string filepath);

	std::string get_pubkey_b64();
	std::string get_privkey_b64();
	void set_aes_key(std::string aes_key);

	std::string get_encrypted_filecontent();
	bool compare_checksum(unsigned long checksum);

	void import_private_key(std::string base64_priv_key);
};
