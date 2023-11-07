#include <fstream>
#include <sstream>
#include <filesystem>
#include <iostream>
#include <vector>

#include "MeInfo.h"
#include "Utils.h"

namespace fs = std::filesystem;

MeInfo::MeInfo() {};

bool MeInfo::read_file() {
	fs::path path { this->filepath };

	if (!fs::exists(path)) {
		return false;
	}

	// read transfer.info filecontent
	std::ifstream file(this->filepath);
	std::stringstream buffer;
	buffer << file.rdbuf();
	this->filecontent = buffer.str();

	std::vector<std::string> file_lines = split_lines(filecontent);

	if (file_lines.size() != 3) {
		err_n_die("Invalid format for me.info");
	}

	this->username = file_lines.at(0);
	this->uuid = file_lines.at(1);
	this->base64_priv_key = file_lines.at(2);

	if (this->username.length() > 100) {
		err_n_die("Username too long (from me.info)");
	}

	return true;
}

void MeInfo::write_file(std::string username, std::string uuid, std::string base64_priv_key) {
	fs::path path { this->filepath };

	std::ofstream ofs(path);
	ofs << username << "\n";
	ofs << uuid << "\n";
	ofs << base64_priv_key;

	ofs.close();
}

std::string MeInfo::get_username() { return this->username; }
std::string MeInfo::get_uuid() { return this->uuid; }
std::string MeInfo::get_base64_priv_key() { return this->base64_priv_key; }
