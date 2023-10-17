#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <array>
#include <netdb.h>
#include <link.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <cstdint>
#include <vector>
#include <string>
#include <set>
#include <errno.h>
#include <filesystem>
#include <utility>
#include <map>
#include <string_view>
#include <charconv>
#include <stdarg.h>

//ssize_t read(int fd, void *buf, size_t count);
//
//ssize_t write(int fd, const void *buf, size_t count);
//
//int open(const char *pathname, int flags, mode_t mode);
//
//int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
//
//int getaddrinfo(const char *node, const char *service,
//                       const struct addrinfo *hints,
//                       struct addrinfo **res);
//
//int system(const char *command);

using libc_start_main_ptr_t = int(*) (int * (int, char * *, char * *), int,  char **, void (*) (void), void (*) (void), void (*) (void), void (*));

using read_ptr_t = ssize_t (*)(int fd, void *buf, size_t count);
using write_ptr_t = ssize_t (*)(int fd, const void *buf, size_t count);
using open_ptr_t = int (*)(const char *pathname, int flags, ...);
using connect_ptr_t = int (*)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
using getaddrinfo_ptr_t = int (*)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
using system_ptr_t = int (*)(const char *command);
using close_ptr_t = int(*)(int fd);

union FunctionPointer{
    read_ptr_t read;
    write_ptr_t write;
    open_ptr_t open;
    connect_ptr_t connect;
    getaddrinfo_ptr_t getaddrinfo;
    system_ptr_t system;
    close_ptr_t close;
    void* void_t;
};

template<typename Enumerator, class T, Enumerator N>
class EnumArray : public std::array<T, static_cast<std::size_t>(N)> {
    using parent = std::array<T, static_cast<std::size_t>(N)>;
public:
    T& operator[] (Enumerator e) {
        return parent::operator[](static_cast<std::size_t>(e));
    }
    const T& operator[] (Enumerator e) const {
        return parent::operator[](static_cast<std::size_t>(e));
    }

    T& operator[] (int e) {
        return parent::operator[](e);
    }
    const T& operator[] (int e) const {
        return parent::operator[](e);
    }
};

#ifdef __cplusplus
extern "C" {
    int __libc_start_main(int *(main) (int, char * *, char * *), int argc, 
                        char * * ubp_av, 
                        void (*init) (void), 
                        void (*fini) (void), 
                        void (*rtld_fini) (void), 
                        void (* stack_end));
}
#endif

template<typename T>
concept IntLike2Str = requires (T x) { std::to_string(x); }; // requires-expression

std::string to_str(std::string_view sv){ 
    return "\"" + std::string{ sv } + "\""; 
}
std::string to_str(const char* s){ 
    if(s == NULL)
        return "\"(null)\""; 
    else
        return to_str(std::string_view{ s }); 
}
template<typename T>
std::string to_str(T i) requires IntLike2Str<T> { return std::to_string(i); }
//std::string to_str(const unsigned int i){ return std::to_string(i); }
//std::string to_str(const long i){ return std::to_string(i); }
//std::string to_str(const unsigned long i){ return std::to_string(i); }
std::string to_str(const void* p){ 
    std::stringstream ss;
    ss << p;
    return ss.str();
}

template <typename FirstString, typename... Strings>
std::string argument(FirstString firstString, Strings&&... strings) {
    std::string output{ to_str(firstString)};

    ((output += ", ", output += to_str(strings)), ...);

    return output;
}

enum class Function{
    Read,
    Write,
    Open,
    Connect,
    Getaddrinfo,
    System,
    Close,
    _Size
};

EnumArray<Function, FunctionPointer, Function::_Size> originalFunction;
EnumArray<Function, FunctionPointer, Function::_Size> replaceFunction;

int LOGGER_FD{ atoi(getenv("LOGGER_FD")) };
int pid{ getpid() };

std::set<std::string> openBlackList{};
std::string readBlackList;
std::set<std::pair<uint32_t, int>> connectBlackList{};   //<ip, port>
std::set<std::string> getaddrinfoBlackList{};
std::map<int, int> writeContentFdMapping;

void logger(const char* functionName, const std::string& arguments, int returnValue) {
    dprintf(LOGGER_FD, "[logger] %s(%s) = %d\n", functionName, arguments.c_str(), returnValue);
}

void logger(const char* functionName, const std::string& arguments) {
    dprintf(LOGGER_FD, "[logger] %s(%s)\n", functionName, arguments.c_str());
}

void dump(const char* type, int fd, const void *buf, size_t count) {
    std::string outputFileName{ std::to_string(pid) + "-" + std::to_string(fd) + "-" + std::string{type} + ".log" };
    FILE* contentOutputFile{ fopen(outputFileName.c_str(), "a+") };
    fwrite(buf, 1, count, contentOutputFile);
    fclose(contentOutputFile);
}

static std::map<int,std::string> readBuffer;
int my_close(int fd){
    if(readBuffer.contains(fd))
        readBuffer.erase(readBuffer.find(fd));

    return originalFunction[Function::Close].close(fd);
}

// Define your own read function
ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t ret{ originalFunction[Function::Read].read(fd, buf, count) };

    readBuffer[fd] += (char*)buf;
    if(readBuffer[fd].find(readBlackList) != std::string::npos){     //**c++23
        my_close(fd);
        errno = EIO;
        ret = -1;
    }

    if(ret != -1)
        dump("read", 1, buf, ret);

    logger("read", argument(fd, buf, count), ret);
    return ret;
}

ssize_t my_write(int fd, const void *buf, size_t count) {
    ssize_t ret{ originalFunction[Function::Write].write(fd, buf, count) };

    dump("write", 1, buf, ret);

    logger("write", argument(fd, buf, count), ret);
    return ret;
}

int my_open(const char *pathname, int flags, ...){
    std::string path{ pathname };
    //printf("open is hijack successfully. :)\n");
    if(std::filesystem::is_symlink(path)) {
        path = std::filesystem::read_symlink(path).c_str();
    }
    
    int ret;
    //assume mode = 0 if not required
    mode_t mode{ 0 };
    //black list
    if(openBlackList.contains(path)){
        errno = EACCES;
        ret =  -1;
    }
    else{
        if(__OPEN_NEEDS_MODE(flags)) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t); 
            va_end(args);

            ret = originalFunction[Function::Open].open(path.c_str(), flags, mode);
        }
        else{
            ret = originalFunction[Function::Open].open(path.c_str(), flags);
        }       
    }   
    logger("open", argument(path, flags, mode), ret);
    
    return ret;
}

int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){   
    sockaddr_in* addr_in{ (sockaddr_in*)addr };
    const char* ip_str{ inet_ntoa(addr_in->sin_addr)};
    uint32_t ip{ inet_addr(ip_str) };
    int port{ ntohs(addr_in->sin_port) };

    //printf("connect to %d: %u:%d\n", sockfd, ip, port);
    int ret;
    if(connectBlackList.contains({ip, port})){
        errno = ECONNREFUSED;
        ret = -1;
    }
    else{
        ret = originalFunction[Function::Connect].connect(sockfd, addr, addrlen);
    }

    logger("connect", argument(sockfd, ip_str, (int)addrlen), ret);

    return ret;
}

int my_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res){
    int ret;
    if(getaddrinfoBlackList.contains(std::string{ node }))
        ret = EAI_NONAME;
    else
        ret = originalFunction[Function::Getaddrinfo].getaddrinfo(node, service, hints, res);

    logger("getaddrinfo", argument(node, service, (void*)hints, (void*)res), ret);
    return ret;
}

int my_system(const char *command){
    logger("system", argument(command));
    return originalFunction[Function::System].system(command);
}

void checkAndReplaceFunction(std::uintptr_t gotAddress){
    void* value{ *reinterpret_cast<void**>(gotAddress) };

    for(int i = 0; i < (int)Function::_Size; i++){
        if (value == originalFunction[i].void_t) {
            //printf("replace %d function success\n", i);
            *reinterpret_cast<void**>(gotAddress) = replaceFunction[i].void_t;  
            break;
        }
    }
}

void addConnectBlackList(std::string_view sv) {
    auto splitPos{ sv.find_first_of(":")};
    std::string name{ sv.substr(0, splitPos) };
    std::string_view p{sv.substr(splitPos+1)};
    int port;
    std::from_chars(p.data(), p.data() + p.size(), port);

    //printf("%s\n", name.c_str());
    hostent* hostname;
    if ((hostname = gethostbyname(name.c_str())) != NULL) {
        in_addr** addr_list = (struct in_addr **)hostname->h_addr_list;
        for(int i = 0; addr_list[i] != NULL; i++) {
            //printf("%s:%d\n", std::string(inet_ntoa(*addr_list[i])).c_str(), port);
            connectBlackList.insert({*(uint32_t*)addr_list[i], port});
        }
    }
}

void addOpenBlackList(std::string_view path) {
    std::filesystem::path p;
    if(std::filesystem::is_symlink(path)) {
        p = std::filesystem::read_symlink(path);
        path = p.c_str();
    }
    openBlackList.insert(std::string{ path });
}

void blacklistInit(){
    const char* config{ getenv("SANDBOX_CONFIG") };

    FILE* configFile{ fopen(config, "r")};

    enum class BlackList{
        Open,
        Read,
        Connect,
        Getaddrinfo,
        Null,
    } currentBlackList{ BlackList::Null };
    static constexpr EnumArray<BlackList, const char*, BlackList::Null> functionName{
        "open", "read", "connect", "getaddrinfo"
    };

    char line[1024]{};
    while(fgets(line, sizeof(line), configFile) != NULL) {
        std::string_view line_sv{ line };
        if(line_sv.ends_with("\n"))
            line_sv.remove_suffix(1);

        using namespace std::string_view_literals;

        static constexpr std::string_view blacklistStartPrefix{ "BEGIN " };
        static constexpr std::string_view blacklistEndPrefix{ "END " };
        static constexpr std::string_view blacklistSuffix{ "-blacklist" };
        if(currentBlackList == BlackList::Null) {
            if(line_sv.starts_with(blacklistStartPrefix) && line_sv.ends_with(blacklistSuffix)){
                line_sv.remove_prefix(blacklistStartPrefix.size());
                line_sv.remove_suffix(blacklistSuffix.size());
                
                if     (line_sv == "open")        currentBlackList = BlackList::Open;
                else if(line_sv == "read")        currentBlackList = BlackList::Read;
                else if(line_sv == "connect")     currentBlackList = BlackList::Connect;
                else if(line_sv == "getaddrinfo") currentBlackList = BlackList::Getaddrinfo;
            }
            continue;
        }
        else {
            if(line_sv.starts_with(blacklistEndPrefix) && line_sv.ends_with(blacklistSuffix)){
                line_sv.remove_prefix(blacklistEndPrefix.size());
                line_sv.remove_suffix(blacklistSuffix.size());
                if(line_sv == functionName[currentBlackList]){
                    currentBlackList = BlackList::Null;
                    continue;
                }
            }

            switch(currentBlackList) {
            case BlackList::Open:        addOpenBlackList(line_sv); break;
            case BlackList::Read:        readBlackList = line_sv; break;
            case BlackList::Connect:     addConnectBlackList(line_sv); break;
            case BlackList::Getaddrinfo: getaddrinfoBlackList.insert(std::string{line_sv}); break;
            }
        }
    }

    fclose(configFile);
}

void printMemoryStruct(){
    FILE *fp{ fopen("/proc/self/maps", "r") };
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
      printf("%s",line);
    }
    fclose(fp);
}

int __libc_start_main(int *(main) (int, char * *, char * *), int argc, 
                        char * * ubp_av, 
                        void (*init) (void), 
                        void (*fini) (void), 
                        void (*rtld_fini) (void), 
                        void (* stack_end)){
    // Get a pointer to the original starting function
    // although the orginal binary have no symbol
    // the libc have these symbol and it also dynamic load and so I can get it
    auto original_libc_start_main { reinterpret_cast<libc_start_main_ptr_t>(dlsym(RTLD_NEXT, "__libc_start_main")) };
    if (original_libc_start_main == NULL) {
        fprintf(stderr, "Error getting symbol: %s\n", dlerror());
        exit(1);
    }

    //printf("logger fd: %d\n",  LOGGER_FD);

    blacklistInit();
    originalFunction[Function::Read].read               = (read);
    originalFunction[Function::Write].write             = (write);
    originalFunction[Function::Open].open               = (open);
    originalFunction[Function::Connect].connect         = (connect);
    originalFunction[Function::Getaddrinfo].getaddrinfo = (getaddrinfo);
    originalFunction[Function::System].system           = (system);
    originalFunction[Function::Close].close             = (close);
    replaceFunction [Function::Read].read               = (my_read);
    replaceFunction [Function::Write].write             = (my_write);
    replaceFunction [Function::Open].open               = (my_open);
    replaceFunction [Function::Connect].connect         = (my_connect);
    replaceFunction [Function::Getaddrinfo].getaddrinfo = (my_getaddrinfo);
    replaceFunction [Function::System].system           = (my_system);
    replaceFunction [Function::Close].close             = (my_close);

    std::uintptr_t gotStart{};
    void *handle { dlopen(NULL, RTLD_LAZY) };
    // Get the address of the dynamic linker table
    struct link_map *map;
    dlinfo(handle, RTLD_DL_LINKMAP, &map);
    for (ElfW(Dyn) *dyn = map->l_ld; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_PLTGOT) {
            gotStart = reinterpret_cast<std::uintptr_t>(dyn->d_un.d_ptr);
            //printf("got start: 0x%lx\n", gotStart);
        }
    }
    dlclose(handle);

    //turn off memory protect
    int pageSize { sysconf(_SC_PAGESIZE) }; // get page size
    std::uintptr_t pageStart { gotStart & ~(pageSize-1) };
    int pageCount{ 1 };
    //fprintf(stderr,"%p %d\n", pageStart, pageSize);
    while(1){
        if(mprotect((void*)pageStart, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC)==-1){
            //perror("mprotect error");
            break;
        }
        pageStart += pageSize;
        pageCount++;
    }
    //printf("page Count:%d", pageCount);
    //printf("read position:%p\n",        originalFunction[Function::Read]);
    //printf("write position:%p\n",       originalFunction[Function::Write]);
    //printf("open position:%p\n",        originalFunction[Function::Open]);
    //printf("connect position:%p\n",     originalFunction[Function::Connect]);
    //printf("getaddrinfo position:%p\n", originalFunction[Function::Getaddrinfo]);
    //printf("system position:%p\n",      originalFunction[Function::System]);
    //printf("total:%d\n", 0x1000*pageCount - (int)(gotStart - (gotStart & ~(pageSize-1))));
    for(int i = 0; gotStart+i < pageStart; i+=8){
        //void* value = *(void**)(gotStart+i);
        //printf("offset: %d, position:%p, value: %p\n", i/8, gotStart+i, value);
        checkAndReplaceFunction(gotStart+i);
    }

    // Call the original starting function
    return original_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

