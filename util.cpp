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

template <typename TP>
std::time_t to_time_t(TP tp)
{
    using namespace std::chrono;
    auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
        + system_clock::now());
    return system_clock::to_time_t(sctp);
}
