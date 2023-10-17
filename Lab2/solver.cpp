#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

std::vector<std::string> files;

void iterate(const char* folderPath){
    for(const auto& file : std::filesystem::directory_iterator(folderPath)) {
        const std::string& filePath{ file.path() };

        std::error_code ec;
        if(std::filesystem::is_symlink(filePath))
            continue;
        if(std::filesystem::is_directory(filePath, ec))
            iterate(filePath.c_str());
        else
            files.push_back(filePath);
    }
}

int main(int argc, char* argv[]) {
    if(argc < 3){
        fprintf(stderr, "use ./solver <dir> <number>\n.");
        exit(0);
    }
    
    const char* folderPath{ argv[1] };
    fprintf(stderr, "folder: %s\n", folderPath);
    int targetNumber{ atoi(argv[2]) };
    fprintf(stderr, "target: %d\n", targetNumber);

    iterate(folderPath);

    for(const auto& filePath : files) {
        fprintf(stderr, "check file: %s\n", filePath.c_str());
        FILE* fd{ fopen(filePath.c_str(), "r") };

        int number{};

        fscanf(fd, "%d", &number);

        if(number == targetNumber){
            fprintf(stderr, "found: %s\n", filePath.c_str());
            printf("%s", filePath.c_str());
            break;
        }
    }
}