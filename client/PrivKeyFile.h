#pragma once
#include <string>

class PrivKeyFile {
private:
	const char* filepath = "priv.key";
public:
	PrivKeyFile();

	void write_b64_priv_key(std::string b64_priv_key);
	std::string get_b64_priv_key();
};
