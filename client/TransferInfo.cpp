#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>

#include "TransferInfo.h"
#include "Utils.h"

namespace fs = std::filesystem;

TransferInfo::TransferInfo() {
	fs::path path { this->filepath };

	if (!fs::exists(path)) {
		err_n_die("File transfer.info does not exist");
	}

	// read transfer.info filecontent
	std::ifstream file(this->filepath);
	std::stringstream buffer;
	buffer << file.rdbuf();
	this->filecontent = buffer.str();
	
	std::vector<std::string> file_lines = split_lines(filecontent);

	if (file_lines.size() != 3) {
		err_n_die("Invalid format for transfer.info");
	}

	this->host_addr = file_lines.at(0);
	this->username = file_lines.at(1);
	this->target_filepath = file_lines.at(2);

	if (this->username.length() > 100) {
		err_n_die("Username too long (from transfer.info)");
	}
}

std::string TransferInfo::get_host_addr() { return this->host_addr; }
std::string TransferInfo::get_username() { return this->username; }
std::string TransferInfo::get_target_filepath() { return this->target_filepath; }
