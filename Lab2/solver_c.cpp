#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>

std::vector<std::string> files;

void iterate(const char* folderPath){
    //fprintf(stderr, "iterate folder: %s\n", folderPath);
    dirent *dp;
    DIR *dirFd{ opendir(folderPath)};
    char filename[350]{};
    while ((dp = readdir(dirFd)) != NULL) {
        struct stat statBuffer{};
        if(dp->d_name[0] == '.' && strlen(dp->d_name) == 1)
            continue;
        if(dp->d_name[1] == '.' && strlen(dp->d_name) == 2)
            continue;
        sprintf(filename , "%s/%s", folderPath, dp->d_name) ;
        if( lstat(filename, &statBuffer) == -1) {
            printf("Unable to stat file: %s\n",filename) ;
            continue;
        }

        if((statBuffer.st_mode & S_IFMT) == S_IFLNK)
            continue;
        if ((statBuffer.st_mode & S_IFMT) == S_IFDIR)  {//dir
            iterate(filename);
            continue;
        }
        
        files.push_back(filename);
    }   
}

int main(int argc, char* argv[]) {
    if(argc < 3){
        fprintf(stderr, "use ./solver <dir> <number>\n.");
        exit(0);
    }
    
    const char* folderPath{ argv[1] };
    fprintf(stderr, "folder: %s\n", folderPath);
    const char* targetNumber{ argv[2] };
    fprintf(stderr, "target: %s\n", targetNumber);

    iterate(folderPath);

    fprintf(stderr, "iterate finish!\n");
    for(const auto& filePath : files) {
        fprintf(stderr, "check file: %s\n", filePath.c_str());
        FILE* fd{ fopen(filePath.c_str(), "r") };

        char number[64]{};

        if(errno != 0) {
            perror("fopen error: ");
            continue;
        }

        fscanf(fd, "%s", number);

        if(strcmp(number,targetNumber)==0){
            fprintf(stderr, "found: %s\n", filePath.c_str());
            printf("%s", filePath.c_str());
            break;
        }
    }
}