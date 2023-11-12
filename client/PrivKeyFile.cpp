#include <fstream>
#include <sstream>
#include <filesystem>

#include "PrivKeyFile.h"
#include "Utils.h"

namespace fs = std::filesystem;

PrivKeyFile::PrivKeyFile() {}

void PrivKeyFile::write_b64_priv_key(std::string b64_priv_key) {
	fs::path path { this->filepath };

	std::ofstream ofs(path);
	ofs << b64_priv_key;

	ofs.close();
}

// this method should only run if "me.info" file exists
std::string PrivKeyFile::get_b64_priv_key() {
	fs::path path { this->filepath };

	if (!fs::exists(path)) {
		err_n_die("priv.key file not found whilst detected previous user login");
	}

	// read transfer.info filecontent
	std::ifstream file(this->filepath);
	std::stringstream buffer;
	buffer << file.rdbuf();
	return std::string(buffer.str());
}
