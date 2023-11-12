#include <iostream>
#include <string>
#include <vector>

void err_n_die(const char* err_msg) {
	std::cout << "[ERROR] " << err_msg << std::endl;
	exit(1);
}

std::vector<std::string> split_lines(std::string filecontent) {
	filecontent += '\0';

	// splitting the file content by newlines
	std::vector<std::string> file_lines;
	std::string current_line = "";
	for (int i = 0; i < filecontent.length(); i++) {
		char current_char = filecontent.at(i);

		if (current_char == '\n' || current_char == '\0') {
			file_lines.push_back(current_line);
			current_line = "";
			continue;
		}

		current_line += current_char;
	}

	return file_lines;
}
