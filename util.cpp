#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
namespace fs = std::filesystem;

// migrate OS specific stuff later
#include <Shlobj.h>

std::vector<char> file2vec(std::string path)
{
	std::ifstream is((char *)(path.c_str()), std::ios::in | std::ios::binary | SH_DENYNO);
	is.seekg(0, std::ios_base::end);
	std::size_t sample_size = is.tellg();
	is.seekg(0, std::ios_base::beg);
	std::vector<char> bytes(sample_size);

	//printf("SAMPLE SIZE: %d", sample_size);
	// Load the data
	is.read(&bytes[0], sample_size);
	// Close the file
	is.close();

	return bytes;
}


// dead code, switched to using fs::is_directory()
bool dir_exists(char *path) {
	struct stat st;
	int ret = stat(path, &st);
	if (ret != 0)
	{
		if (errno == ENOENT) { return 0; } // something along the path does not exist
		if (errno == ENOTDIR) { return 0; } // something in path prefix is not a dir
		return -1;
	}

	return (st.st_mode & S_IFDIR) ? 1 : 0;
}

bool dir_create(char* path) {
	if (SHCreateDirectoryExA(NULL, path, NULL) == ERROR_SUCCESS)
		return true;

	return false;
}

template <typename TP>
std::time_t to_time_t(TP tp)
{
	using namespace std::chrono;
	auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
		+ system_clock::now());
	return system_clock::to_time_t(sctp);
}

struct tm* last_modified(fs::path const& p) {
	auto ftime = fs::last_write_time(p);
	auto cftime = to_time_t(ftime);
	return std::localtime(&cftime);
}
