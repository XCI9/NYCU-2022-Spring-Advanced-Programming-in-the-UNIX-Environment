#include <capstone/capstone.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>  //process_vm_readv
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace std::string_view_literals;

void errquit(const char* msg) {
    perror(msg);
    exit(-1);
}

class Command {
    std::string m_fullCommand;
    std::vector<std::string_view> m_commandList;

    void generateCommandList() {
        std::string_view input{ m_fullCommand };

        // remove space like char at start and end
        input = input.substr(0, input.find_last_not_of("\r\n \t") + 1);
        // printf("%s %lu\n", input.data(), input.size());
        input = input.substr(input.find_first_not_of("\r\n \t"));

        std::string_view spliter{ " " };
        for (const auto word : std::views::split(input, spliter))
            m_commandList.emplace_back(word.begin(), word.end());
    }

   public:
    Command() : m_fullCommand{ "" } {}

    Command(std::string_view fullCommand) : m_fullCommand{ fullCommand } {
        generateCommandList();
    }

    Command(const Command& cmd) {
        m_fullCommand = cmd.m_fullCommand;
        m_commandList = cmd.m_commandList;
    }

    void setCommand(std::string_view fullCommand) {
        m_fullCommand = fullCommand;
        m_commandList.clear();
        generateCommandList();
    }

    std::string_view getFullCommand() const { return m_fullCommand; }

    const std::vector<std::string_view>& getCommandList() {
        return m_commandList;
    }

    std::size_t size() const { return m_commandList.size(); }

    bool empty() const { return m_commandList.empty(); }

    void print() const {
        printf("cmd: ");
        for (const auto& command : m_commandList)
            printf("%.*s, ", static_cast<int>(command.size()), command.data());
        printf("end\n");
    }

    std::string_view operator[](const std::size_t i) const {
        // if (m_commandList.size() <= i)
        //     throw Error { Response::ERR_NEEDMOREPARAMS };

        return m_commandList[i];
    }

    operator std::string_view() const { return m_fullCommand; }
};

class ELFParser {
    Elf64_Ehdr m_elfHeader;
    Elf64_Shdr m_stringSectionHeader;
    FILE* m_fd;

    Elf64_Shdr getSectionHeader(Elf64_Off n) const {
        Elf64_Shdr sectionHeader;
        fseeko(m_fd, m_elfHeader.e_shoff + n * m_elfHeader.e_shentsize,
               SEEK_SET);
        fread(&sectionHeader, sizeof(sectionHeader), 1, m_fd);
        return sectionHeader;
    }

    Elf64_Phdr getProgramHeader(Elf64_Off n) const {
        Elf64_Phdr programHeader;
        fseeko(m_fd, m_elfHeader.e_phoff + n * m_elfHeader.e_phentsize,
               SEEK_SET);
        fread(&programHeader, sizeof(programHeader), 1, m_fd);
        return programHeader;
    }

    void getSectionFlags(unsigned long int flags, char* buffer) const {
        buffer[0] = (flags & SHF_WRITE) ? 'W' : ' ';
        buffer[1] = (flags & SHF_ALLOC) ? 'A' : ' ';
        buffer[2] = (flags & SHF_EXECINSTR) ? 'X' : ' ';
        buffer[3] = (flags & SHF_MASKPROC) ? 'M' : ' ';
        buffer[4] = '\0';
    }

    void getProgramFlags(unsigned long int flags, char* buffer) const {
        buffer[0] = (flags & PF_X) ? 'X' : ' ';
        buffer[1] = (flags & PF_W) ? 'W' : ' ';
        buffer[2] = (flags & PF_R) ? 'R' : ' ';
        buffer[3] = '\0';
    }

    const char* getSectionType(unsigned int type) const {
        switch (type) {
            case SHT_NULL: return "NULL";
            case SHT_PROGBITS: return "PROGBITS";
            case SHT_SYMTAB: return "SYMTAB";
            case SHT_STRTAB: return "STRTAB";
            case SHT_RELA: return "RELA";
            case SHT_HASH: return "HASH";
            case SHT_DYNAMIC: return "DYNAMIC";
            case SHT_NOTE: return "NOTE";
            case SHT_NOBITS: return "NOBITS";
            case SHT_REL: return "REL";
            case SHT_SHLIB: return "SHLIB";
            case SHT_DYNSYM: return "DYNSYM";
        }
        return "undefined";
    }

    const char* getProgramType(unsigned int type) const {
        switch (type) {
            case PT_NULL: return "NULL";
            case PT_LOAD: return "LOAD";
            case PT_DYNAMIC: return "DYNAMIC";
            case PT_INTERP: return "INTERP";
            case PT_NOTE: return "NOTE";
            case PT_SHLIB: return "SHLIB";
            case PT_PHDR: return "PHDR";
            case PT_GNU_STACK: return "GNU_STACK";
        }
        return "undefined";
    }

   public:
    ELFParser(const char* filename) : m_fd{ fopen(filename, "rb") } {
        fread(&m_elfHeader, sizeof(m_elfHeader), 1, m_fd);
        m_stringSectionHeader = getSectionHeader(m_elfHeader.e_shstrndx);
    }

    void printELFHeader() const {
        printf("type:%hu\n", m_elfHeader.e_type);
        printf("machine:%hu\n", m_elfHeader.e_machine);
        printf("version:%u\n", m_elfHeader.e_version);
        printf("Entry point virtual address:0x%016lx\n", m_elfHeader.e_entry);
        printf("Program header table file offset:0x%016lx\n",
               m_elfHeader.e_phoff);
        printf("Section header table file offset:0x%016lx\n",
               m_elfHeader.e_shoff);
        printf("flags:%u\n", m_elfHeader.e_flags);
        printf("ELF header size in bytes:%hu\n", m_elfHeader.e_ehsize);
        printf("Program header table entry size:%hu\n",
               m_elfHeader.e_phentsize);
        printf("Program header table entry count:%hu\n", m_elfHeader.e_phnum);
        printf("Section header table entry size:%hu\n",
               m_elfHeader.e_shentsize);
        printf("Section header table entry count:%hu\n", m_elfHeader.e_shnum);
        printf("Section header string table index:%hu\n",
               m_elfHeader.e_shstrndx);
    }

    void printProgramHeader() const {
        printf("%-10s|%-5s|%-18s|%-18s|%-18s|%-9s|%-11s|%-6s|\n", "type",
               "flags", "virtual address", "physics address", "offset",
               "file size", "memory size", "align");
        for (Elf64_Off i{ 0 }; i < m_elfHeader.e_phnum; i++) {
            Elf64_Phdr programHeader{ getProgramHeader(i) };

            char flags[4]{};
            getProgramFlags(programHeader.p_flags, flags);

            printf(
                "%-10s|%-5s|0x%016lx|0x%016lx|0x%016lx|0x%-7lx|0x%-9lx|0x%-4lx|"
                "\n",
                getProgramType(programHeader.p_type), flags,
                programHeader.p_vaddr, programHeader.p_paddr,
                programHeader.p_offset, programHeader.p_filesz,
                programHeader.p_memsz, programHeader.p_align);
        }
    }

    void printSectionHeader() const {
        printf("%-20s|%-10s|%-5s|%-18s|%-18s|%-7s|%-4s|%-4s|%-12s|%-7s|\n",
               "name", "type", "flags", "address", "offset", "size", "link",
               "info", "addressAlign", "entsize");
        for (Elf64_Off i{ 0 }; i < m_elfHeader.e_shnum; i++) {
            Elf64_Shdr sectionHeader{ getSectionHeader(i) };

            if (sectionHeader.sh_type == SHN_UNDEF) continue;

            char name[128]{};
            char flags[5]{};
            fseeko(m_fd,
                   m_stringSectionHeader.sh_offset + sectionHeader.sh_name,
                   SEEK_SET);
            fread(name, 128, 1, m_fd);
            getSectionFlags(sectionHeader.sh_flags, flags);

            printf(
                "%-20s|%-10s|%-5s|0x%016lx|0x%016lx|%-7lu|%-4u|%-4u|%-12lu|%-"
                "7lu|\n",
                name, getSectionType(sectionHeader.sh_type), flags,
                sectionHeader.sh_addr, sectionHeader.sh_offset,
                sectionHeader.sh_size, sectionHeader.sh_link,
                sectionHeader.sh_info, sectionHeader.sh_addralign,
                sectionHeader.sh_entsize);
        }
    }

    int getEntryPoint() const { return m_elfHeader.e_entry; }

    unsigned long getCodeEnd() const {
        for (Elf64_Off i{ 0 }; i < m_elfHeader.e_phnum; i++) {
            Elf64_Phdr programHeader{ getProgramHeader(i) };

            if (programHeader.p_type != PT_LOAD) continue;

            if (programHeader.p_flags & PF_X)
                return programHeader.p_paddr + programHeader.p_memsz;
        }
        return -1ul;
    }

    // is Position Independent Executable
    bool isPIE() const { return m_elfHeader.e_type == ET_DYN; }

    ~ELFParser() { fclose(m_fd); }
};

class Debugger {
    struct Memory {
        unsigned long long address;
        std::vector<char> data;
    };

    struct AnchorPoint {
        std::vector<Memory> memories;
        user_regs_struct regs;
        bool valid{ false };

        bool isValid() const { return valid; }

        void snapshot(int pid) {
            valid = true;
            memories.clear();

            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
                errquit("ptrace@parent");

            char proc_maps_path[256];
            snprintf(proc_maps_path, sizeof(proc_maps_path), "/proc/%d/maps",
                     pid);

            FILE* maps_file = fopen(proc_maps_path, "r");
            if (maps_file == NULL) {
                perror("Failed to open /proc/pid/maps");
                exit(1);
            }

            unsigned long start_address, end_address;
            char permissions[5];  // rwxp
            char path[256];
            int ret;
            char line[512];
            while (fgets(line, sizeof(line), maps_file) != NULL) {
                sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s\n", &start_address,
                       &end_address, permissions, path);

                if (permissions[1] == 'w') {  // writable
                    Memory memory;
                    memory.address = start_address;
                    memory.data.resize(end_address - start_address);
                    memories.push_back(memory);
                }
                // printf("%c %c %c %c\n", permissions[0], permissions[1],
                // permissions[2], permissions[3]);
            }

            fclose(maps_file);

            for (auto& memory : memories) {
                iovec local, remote;
                local.iov_base = memory.data.data();
                local.iov_len = memory.data.size();
                remote.iov_base = (void*)memory.address;
                remote.iov_len = memory.data.size();
                if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0)
                    errquit("vm_readv@parent");
            }
        }

        void timetravel(int pid) {
            if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0)
                errquit("ptrace@parent");

            for (auto& memory : memories) {
                iovec local, remote;
                local.iov_base = memory.data.data();
                local.iov_len = memory.data.size();
                remote.iov_base = (void*)memory.address;
                remote.iov_len = memory.data.size();
                if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0)
                    errquit("vm_writev@parent");
            }
        }
    } m_anchorPoint;

    Command m_command;
    Command m_previousCommand;
    pid_t m_childPid;
    std::map<unsigned long long, unsigned char> m_breakpoint;
    ELFParser m_elfInfo;
    unsigned long long m_childBaseAddress;
    unsigned long long m_entryAddress;
    unsigned long long m_CodeEndAddress;
    csh m_cshandle{};

    unsigned long getChildBaseAddress() {
        char proc_maps_path[256];
        snprintf(proc_maps_path, sizeof(proc_maps_path), "/proc/%d/maps",
                 m_childPid);

        FILE* maps_file = fopen(proc_maps_path, "r");
        if (maps_file == NULL) {
            perror("Failed to open /proc/pid/maps");
            exit(1);
        }

        unsigned long base_address = 0;

        // Read the first entry from /proc/pid/maps
        unsigned long start_address, end_address;
        char permissions[5];
        char path[256];
        int ret = fscanf(maps_file, "%lx-%lx %4s %*s %*s %*s %255s\n",
                         &start_address, &end_address, permissions, path);

        if (ret != 4) {
            perror("Failed to read /proc/pid/maps");
            exit(1);
        }

        base_address = start_address;

        fclose(maps_file);

        return base_address;
    }

    void setupEntryAddress() {
        if (m_elfInfo.isPIE())
            m_entryAddress = m_elfInfo.getEntryPoint() + m_childBaseAddress;
        else m_entryAddress = m_elfInfo.getEntryPoint();
    }

    void dumpCode(long address) {
        static constexpr int DUMPSIZE{ 15 * 5 };
        unsigned char code[DUMPSIZE + 1];
        for (int i{ 0 }; i < DUMPSIZE; i += 8) {
            long long peek{ ptraceChild(PTRACE_PEEKTEXT, (void*)(address + i),
                                        NULL) };
            memcpy(&code[i], &peek, 8);
        }

        // replace breakpoint with original code
        // for (auto nextBreakPoint{ m_breakpoint.lower_bound(address) };
        //     nextBreakPoint != m_breakpoint.end(); nextBreakPoint++) {
        //    const auto& [breakpointAddress, orginalCode]{ *nextBreakPoint };
        //
        //    // not in display range
        //    if (breakpointAddress >= address + DUMPSIZE) break;
        //
        //    code[breakpointAddress - address] = orginalCode;
        //}

        // diasemble
        cs_insn* insn;
        if (int count; (count = cs_disasm(m_cshandle, (uint8_t*)code, DUMPSIZE,
                                          address, 0, &insn)) > 0) {
            // printf("count: %d\n", count);
            for (int i{ 0 }; i < 5; i++) {
                uint64_t addr{ insn[i].address };
                char* instructionName{ insn[i].mnemonic };
                char* op_str{ insn[i].op_str };
                uint8_t* bytes{ insn[i].bytes };

                if (addr >= m_CodeEndAddress) {
                    printf(
                        "** the address is out of the range of the text "
                        "section.\n");
                    break;
                }
                printf("%16lx:", addr);

                for (int byte{ 0 }; byte < 15; byte++) {
                    if (byte < insn[i].size)
                        printf(" %02x", bytes[byte] & 0xff);
                    else printf("   ");
                }
                printf("%-10s", instructionName);
                printf("%s\n", op_str);
            }
            cs_free(insn, count);
        }
    }

    unsigned long long svhex2ull(std::string_view sv) const {
        // Remove the leading "0x" if it exists
        if (sv.starts_with("0x")) sv.remove_prefix(2);

        // Convert the hex string to an unsigned long
        std::istringstream iss(
            sv.data());  // * string_view may not null end, but
                         // the case I use always null terminate
        unsigned long ull;
        iss >> std::hex >> ull;
        return ull;
    }

   public:
    Debugger(char* argv[])
        : m_elfInfo{ argv[1] }, m_CodeEndAddress{ m_elfInfo.getCodeEnd() } {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_cshandle) != CS_ERR_OK)
            exit(-1);

        if ((m_childPid = fork()) < 0) errquit("fork");
        if (m_childPid == 0) {
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
            execvp(argv[1], argv + 1);
            errquit("execvp");
        } else {
            int wait_status;
            if (waitpid(m_childPid, &wait_status, 0) < 0) errquit("waitpid");
            ptrace(PTRACE_SETOPTIONS, m_childPid, 0,
                   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);
        }

        if (m_elfInfo.isPIE()) {
            m_childBaseAddress = getChildBaseAddress();
            m_CodeEndAddress += m_childBaseAddress;
        }
        setupEntryAddress();
        printf("** program '%s' loaded. entry point 0x%llx\n", argv[1],
               m_entryAddress);

        insertBreakpoint(m_entryAddress);

        ptraceChild(PTRACE_CONT, 0, 0);
        waitChild();

        struct user_regs_struct regs;
        ptraceChild(PTRACE_GETREGS, 0, &regs);
        restoreBreakpoint(regs.rip - 1);
        dumpCode(regs.rip - 1);
    }

    long ptraceChild(__ptrace_request request, void* addr, void* data) {
        errno = 0;
        long returnValue{ ptrace(request, m_childPid, addr, data) };
        if (errno < 0) {
            switch (request) {
                case PTRACE_PEEKTEXT: errquit("ptrace PEEKTEXT@parent");
                case PTRACE_POKETEXT: errquit("ptrace POKETEXT@parent");
                case PTRACE_PEEKUSER: errquit("ptrace PEEKUSER@parent");
                case PTRACE_POKEUSER: errquit("ptrace POKEUSER@parent");
                case PTRACE_SINGLESTEP: errquit("ptrace SINGLESTEP@parent");
                case PTRACE_GETREGS: errquit("ptrace GETREGS@parent");
                case PTRACE_SETREGS: errquit("ptrace SETREGS@parent");
                case PTRACE_CONT: errquit("ptrace CONT@parent");
                default: errquit("ptrace@parent");
            }
        }
        return returnValue;
    }

    void insertBreakpoint(unsigned long long address) {
        long value{ ptraceChild(PTRACE_PEEKTEXT, (void*)address, 0) };
        char originalValue{ static_cast<char>(value & 0xff) };
        m_breakpoint[address] = originalValue;

        struct user_regs_struct registers;
        ptraceChild(PTRACE_GETREGS, 0, &registers);
        if (registers.rip != address || address == m_entryAddress) {
            ptraceChild(PTRACE_POKETEXT, (void*)address,
                        (void*)(0xcc | (0xffffffffffffff00 & value)));
        }
    }

    // insert an already exists breakpoint back
    void reinsertBreakpoint(unsigned long long address) {
        long value{ ptraceChild(PTRACE_PEEKTEXT, (void*)address, 0) };
        char originalValue{ static_cast<char>(value & 0xff) };

        ptraceChild(PTRACE_POKETEXT, (void*)address,
                    (void*)(0xcc | (0xffffffffffffff00 & value)));
    }

    // restore 0xcc to original code
    void restoreBreakpoint(unsigned long long address) {
        unsigned char orignalCode{ m_breakpoint[address] };
        long value{ ptraceChild(PTRACE_PEEKTEXT, (void*)address, 0) };
        // printf("%lx\n", value);
        value = orignalCode | (0xffffffffffffff00 & value);
        // printf("%lx\n", value);
        ptraceChild(PTRACE_POKETEXT, (void*)address, (void*)value);
        // struct user_regs_struct regs;
        // if (ptrace(PTRACE_GETREGS, m_childPid, 0, &regs) != 0)
        //     errquit("ptrace@parent SETREGS");
        // regs.rip = address;
        // if (ptrace(PTRACE_SETREGS, m_childPid, 0, &regs) != 0)
        //     errquit("ptrace@parent SETREGS");

        ptraceChild(PTRACE_POKEUSER, (void*)(sizeof(long) * REG_RIP),
                    (void*)address);
    }

    bool checkBreakPoint(unsigned long long address) {
        if (m_breakpoint.contains(address)) {
            printf("** hit a breakpoint at 0x%llx\n", address);
            restoreBreakpoint(address);
            return true;
        }
        return false;
    }

    void cmd_breakpoint(unsigned long long address) {
        // entry point is always an auto breakpoint
        if (address == m_entryAddress) {
            printf("** set a breakpoint at 0x%llx.\n", address);
            return;
        }

        if (m_breakpoint.contains(address)) {  // already breakpoint
            printf("** breakpoint at 0x%llx already existed.\n", address);
            return;
        }

        printf("** set a breakpoint at 0x%llx.\n", address);
        insertBreakpoint(address);
    }

    void cmd_continue() {
        struct user_regs_struct regs;
        ptraceChild(PTRACE_GETREGS, 0, &regs);

        // run single step, and insert back the breakpoint
        unsigned long long address{ regs.rip };
        if (m_breakpoint.contains(address)) {
            ptraceChild(PTRACE_SINGLESTEP, 0, 0);
            waitChild();

            // insert breakpoint
            reinsertBreakpoint(address);
        }
        ptraceChild(PTRACE_CONT, 0, 0);
        waitChild();
        struct user_regs_struct registers;
        ptraceChild(PTRACE_GETREGS, 0, &registers);
        bool isStopByBreakPoint{ checkBreakPoint(registers.rip - 1) };
        if (isStopByBreakPoint) registers.rip -= 1;
        dumpCode(registers.rip);
    }

    void cmd_stepInstruction() {
        struct user_regs_struct previousRegisters;
        ptraceChild(PTRACE_GETREGS, 0, &previousRegisters);
        ptraceChild(PTRACE_SINGLESTEP, 0, 0);

        waitChild();

        // last instruction is breakpoint
        if (m_breakpoint.contains(previousRegisters.rip))
            reinsertBreakpoint(previousRegisters.rip);

        // the following instruction is breakpoint
        struct user_regs_struct registers;
        ptraceChild(PTRACE_GETREGS, 0, &registers);
        checkBreakPoint(registers.rip);
        dumpCode(registers.rip);
    }

    void cmd_anchor() {
        m_anchorPoint.snapshot(m_childPid);
        printf("** dropped an anchor\n");
    }

    void cmd_timetravel() {
        if (!m_anchorPoint.isValid()) {
            printf("** anchor point not exist\n");
            return;
        }

        struct user_regs_struct previousRegisters;
        ptraceChild(PTRACE_GETREGS, 0, &previousRegisters);
        unsigned long long address{ previousRegisters.rip };
        if (m_breakpoint.contains(address)) {
            reinsertBreakpoint(address);
        }

        printf("** go back to the anchor point\n");
        m_anchorPoint.timetravel(m_childPid);

        // the following instruction is breakpoint
        struct user_regs_struct registers;
        ptraceChild(PTRACE_GETREGS, 0, &registers);
        // checkBreakPoint(registers.rip);
        // checkBreakPoint without printing "hit breakpoint"
        if (m_breakpoint.contains(registers.rip)) {
            // printf("** hit a breakpoint at 0x%llx.\n", address);
            restoreBreakpoint(registers.rip);
        }
        dumpCode(registers.rip);
    }

    void cmd_print() {
        struct user_regs_struct regs;
        ptraceChild(PTRACE_GETREGS, 0, &regs);
        if (m_command.size() == 1) {
            printf("r15\t%llx\n", regs.r15);
            printf("r14\t%llx\n", regs.r14);
            printf("r13\t%llx\n", regs.r13);
            printf("r12\t%llx\n", regs.r12);
            printf("rbp\t%llx\n", regs.rbp);
            printf("rbx\t%llx\n", regs.rbx);
            printf("r11\t%llx\n", regs.r11);
            printf("r10\t%llx\n", regs.r10);
            printf("r9 \t%llx\n", regs.r9);
            printf("r8 \t%llx\n", regs.r8);
            printf("rax\t%llx\n", regs.rax);
            printf("rcx\t%llx\n", regs.rcx);
            printf("rdx\t%llx\n", regs.rdx);
            printf("rsi\t%llx\n", regs.rsi);
            printf("rdi\t%llx\n", regs.rdi);
            printf("rip\t%llx\n", regs.rip);
            printf("rsp\t%llx\n", regs.rsp);
            return;
        }
        if (m_command[1][0] == '%') {  // print register
            if (m_command[1] == "%r15") printf("r15\t%llx\n", regs.r15);
            else if (m_command[1] == "%r14") printf("r14\t%llx\n", regs.r14);
            else if (m_command[1] == "%r13") printf("r13\t%llx\n", regs.r13);
            else if (m_command[1] == "%r12") printf("r12\t%llx\n", regs.r12);
            else if (m_command[1] == "%rbp") printf("rbp\t%llx\n", regs.rbp);
            else if (m_command[1] == "%rbx") printf("rbx\t%llx\n", regs.rbx);
            else if (m_command[1] == "%r11") printf("r11\t%llx\n", regs.r11);
            else if (m_command[1] == "%r10") printf("r10\t%llx\n", regs.r10);
            else if (m_command[1] == "%r9") printf("r9 \t%llx\n", regs.r9);
            else if (m_command[1] == "%r8") printf("r8 \t%llx\n", regs.r8);
            else if (m_command[1] == "%rax") printf("rax\t%llx\n", regs.rax);
            else if (m_command[1] == "%rcx") printf("rcx\t%llx\n", regs.rcx);
            else if (m_command[1] == "%rdx") printf("rdx\t%llx\n", regs.rdx);
            else if (m_command[1] == "%rsi") printf("rsi\t%llx\n", regs.rsi);
            else if (m_command[1] == "%rdi") printf("rdi\t%llx\n", regs.rdi);
            else if (m_command[1] == "%rip") printf("rip\t%llx\n", regs.rip);
            else if (m_command[1] == "%rsp") printf("rsp\t%llx\n", regs.rsp);
        }
        if (m_command[1][0] == '$') {  // print elf
            if ("$elfheader"sv.starts_with(m_command[1]))
                m_elfInfo.printELFHeader();
            else if ("$programheader"sv.starts_with(m_command[1]))
                m_elfInfo.printProgramHeader();
            else if ("$sectionheader"sv.starts_with(m_command[1]))
                m_elfInfo.printSectionHeader();

        } else {  // print memory
            unsigned long long address{ svhex2ull(m_command[1]) };
            long value{ ptraceChild(PTRACE_PEEKTEXT, (void*)address, 0) };
            printf("0x%lx\n", value);
        }
    }

    void loop() {
        m_previousCommand = m_command;
        while (1) {
            int status;
            pid_t result = waitpid(m_childPid, &status, WNOHANG);
            if (result != 0) {
                printf("** the target program terminated\n");
                exit(0);
            }
            printf("(sdb) ");
            fflush(stdout);

            // ssize_t size;
            // size = read(fileno(stdin), m_inputBuffer, 1024);
            // m_inputBuffer[size] = '\0';

            char buffer[1024];
            scanf("%1024[^\n]", buffer);
            getchar();

            // nothing input, use previous cmd
            if (strlen(buffer) == 0) m_command = m_previousCommand;
            else m_command.setCommand(buffer);
            // command.print();

            if ("continue"sv.starts_with(m_command[0])) {
                cmd_continue();
                return;
            } else if ("break"sv.starts_with(m_command[0])) {
                cmd_breakpoint(svhex2ull(m_command[1]));
                return;
            } else if ("singleinstruction"sv.starts_with(m_command[0])) {
                cmd_stepInstruction();
                return;
            } else if ("anchor"sv.starts_with(m_command[0])) {
                cmd_anchor();
                return;
            } else if ("timetravel"sv.starts_with(m_command[0]) ||
                       m_command[0] == "tt") {
                cmd_timetravel();
                return;
            } else if ("print"sv.starts_with(m_command[0])) {
                cmd_print();
                return;
            }
        }
    }

    void waitChild() {
        int wait_status;

        if (waitpid(m_childPid, &wait_status, 0) < 0) errquit("waitpid");
        if (wait_status == 0) {
            printf("** the target program terminated\n");
            exit(0);
        }
        // printf("wait status:%d\n", m_childPid);
    }

    ~Debugger() { cs_close(&m_cshandle); }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: ./sdb <program>\n");
        exit(1);
    }

    Debugger debugger{ argv };

    while (1) {
        debugger.loop();
    }
}