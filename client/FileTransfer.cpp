#include "FileTransfer.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "Utils.h"
#include "cksum.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;


std::string read_file(std::string filepath) {
	// read file content
	fs::path path { filepath };

	if (!fs::exists(path)) {
		err_n_die("filepath does not exist!");
	}

	std::ifstream file(filepath, std::ifstream::binary);
	
	std::vector<char> bytes(
		(std::istreambuf_iterator<char>(file)),
		(std::istreambuf_iterator<char>())
	);

	std::string filecontent(bytes.begin(), bytes.end());

	file.close();
	return filecontent;
}

FileTransfer::FileTransfer(std::string filepath) {
	// setup RSA pair
	RSAPrivateWrapper rsapriv;
	std::string pubkey = rsapriv.getPublicKey();

	RSAPublicWrapper rsapub(pubkey);
	std::string pubkey_b64 = Base64Wrapper::encode(pubkey);
	std::string privkey_b64 = Base64Wrapper::encode(rsapriv.getPrivateKey());

	// strip base64 private key from newlines
	// since it needs to follow the format of "transfer.info" and "me.info" files
	std::string result;
	std::remove_copy(privkey_b64.begin(), privkey_b64.end(), std::back_inserter(result), '\n');
	privkey_b64 = std::string(result);

	// calculate checksum
	std::string filecontent = read_file(filepath);
	unsigned long checksum = memcrc((char*)filecontent.c_str(), filecontent.length());

	this->pubkey_b64 = pubkey_b64;
	this->privkey_b64 = privkey_b64;
	this->filepath = filepath;
	this->checksum = checksum;
	this->aes_key = "";
}

void FileTransfer::import_private_key(std::string base64_priv_key) {
	this->privkey_b64 = base64_priv_key;
	this->pubkey_b64 = ""; // irrelevant
}

std::string FileTransfer::get_pubkey_b64() {
	return this->pubkey_b64;
}

std::string FileTransfer::get_privkey_b64() {
	return this->privkey_b64;
}

void FileTransfer::set_aes_key(std::string encrypted_aes_key) {
	std::string decoded_privkey = Base64Wrapper::decode(this->privkey_b64);
	RSAPrivateWrapper rsapriv_other(decoded_privkey);

	std::string aes_key = rsapriv_other.decrypt(encrypted_aes_key);

	this->aes_key = aes_key;
	std::cout << "successfuly set aes key: " << Base64Wrapper::encode(this->aes_key) << std::endl;
}

std::string FileTransfer::get_encrypted_filecontent() {
	std::string filecontent = read_file(this->filepath);

	// encrypt with aes_key
	AESWrapper* aes_wrapper = new AESWrapper((const unsigned char*)this->aes_key.c_str(), 16);
	std::string encrypted_filecontent = aes_wrapper->encrypt(filecontent.c_str(), filecontent.length());
	
	return encrypted_filecontent;
}

bool FileTransfer::compare_checksum(unsigned long checksum) {
	return this->checksum == checksum;
}
