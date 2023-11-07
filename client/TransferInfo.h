#pragma once
#include <string>

class TransferInfo {
private:
	std::string filecontent;
	const char* filepath = "transfer.info";

	std::string host_addr;
	std::string username;
	std::string target_filepath;
public:
	TransferInfo();
	std::string get_host_addr();
	std::string get_username();
	std::string get_target_filepath();
};
