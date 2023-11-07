#pragma once
#include <string>

class MeInfo {
private:
	std::string filecontent;
	const char* filepath = "me.info";

	std::string username;
	std::string uuid;
	std::string base64_priv_key;
public:
	MeInfo();
	bool read_file();
	void write_file(std::string username, std::string uuid, std::string base64_priv_key);

	std::string get_username();
	std::string get_uuid();
	std::string get_base64_priv_key();
};
