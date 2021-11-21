/*
bug-debug: simple debugger
Author: Sudarshan Sundarrajan
*/
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sys/fcntl.h>
#include <algorithm>
#include <vector>
#include "include/linenoise.h"
#include <sstream>
#include <unordered_map>
#include <sys/personality.h>
#include <sys/user.h>
#include "libelfin/dwarf/dwarf++.hh"
#include "libelfin/elf/elf++.hh"

using namespace std;

enum class reg{
    rax, rbx, rcx, rdx, rsi,
    rdi, rbp, rsp, r8, r9, r10,
    r11, r12, r13, r14, r15,
    rip, eflags, cs, orig_rax,
    fs_base, gs_base, fs, gs, ss, ds, es
};

struct reg_desc{
    reg r;
    int dwarf_no;
    string name;
};

const array<reg_desc, 27> reg_descriptors{{
    { reg::r15, 15, "r15" },
    { reg::r14, 14, "r14" },
    { reg::r13, 13, "r13" },
    { reg::r12, 12, "r12" },
    { reg::rbp, 6, "rbp" },
    { reg::rbx, 3, "rbx" },
    { reg::r11, 11, "r11" },
    { reg::r10, 10, "r10" },
    { reg::r9, 9, "r9" },
    { reg::r8, 8, "r8" },
    { reg::rax, 0, "rax" },
    { reg::rcx, 2, "rcx" },
    { reg::rdx, 1, "rdx" },
    { reg::rsi, 4, "rsi" },
    { reg::rdi, 5, "rdi" },
    { reg::orig_rax, -1, "orig_rax" },
    { reg::rip, -1, "rip" },
    { reg::cs, 51, "cs" },
    { reg::eflags, 49, "eflags" },
    { reg::rsp, 7, "rsp" },
    { reg::ss, 52, "ss" },
    { reg::fs_base, 58, "fs_base" },
    { reg::gs_base, 59, "gs_base" },
    { reg::ds, 53, "ds" },
    { reg::es, 50, "es" },
    { reg::fs, 54, "fs" },
    { reg::gs, 55, "gs" },
}};

uint64_t get_reg_val(pid_t pid, reg r){
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    auto it = find_if(reg_descriptors.begin(), reg_descriptors.end(), [r](auto&& rd){ return rd.r == r;});
    return *(reinterpret_cast<uint64_t*> (&regs) + (it - reg_descriptors.begin()));
}

void set_reg_val(pid_t pid, reg r, uint64_t value){
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    auto it = find_if(reg_descriptors.begin(), reg_descriptors.end(), [r](auto&& rd){ return rd.r == r;});
    *(reinterpret_cast<uint64_t*> (&regs) + (it - reg_descriptors.begin())) = value;
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

reg get_reg_name(string &name){
    auto it = find_if(reg_descriptors.begin(), reg_descriptors.end(), [name](auto &&rd) {return rd.name == name;});
    return it->r;
}

uint64_t get_reg_val_dwarf(pid_t pid, uint reg_no){
    auto it = find_if(reg_descriptors.begin(), reg_descriptors.end(), [reg_no](auto&& rd){ return rd.dwarf_no == reg_no;});
    if(it == reg_descriptors.end()){
        throw out_of_range{"Unknown dwarf register!"};
    }
    return get_reg_val(pid, it->r);
}


class ptrace_expr_context : public dwarf::expr_context{
    private:
        pid_t debuggee_pid;
        uint64_t load_addr;
    public:
        ptrace_expr_context(pid_t pid, uint64_t addr){
            debuggee_pid = pid;
            load_addr = addr;
        }
        dwarf::taddr reg(uint reg_no) override {
            return get_reg_val_dwarf(debuggee_pid, reg_no);
        }
        dwarf::taddr pc() override{
            user_regs_struct regs;
            ptrace(PTRACE_GETREGS, debuggee_pid, nullptr, &regs);
            return regs.rip - load_addr;
        }
        dwarf::taddr deref_size(dwarf::taddr addr, uint size) override{
            return ptrace(PTRACE_PEEKDATA, debuggee_pid, addr+load_addr, nullptr);
        }
};

class breakpoint{
    private:
        pid_t debugee_pid;
        intptr_t bp_addr;
        bool bp_enable;
        uint8_t orig_data;
    public:
        breakpoint() = default;
        breakpoint(pid_t pid, intptr_t addr){
            debugee_pid = pid;
            bp_addr = addr;
            bp_enable = false;
        }
        void enable_bp();
        void disable_bp();
        bool is_enabled(){return bp_enable;}
};

void breakpoint::enable_bp(){
    auto data = ptrace(PTRACE_PEEKDATA, debugee_pid, bp_addr, nullptr);
    //cout<<"bug-debug> "<<data<<"\n";
    orig_data = (uint8_t)(data & 0xff);
    uint64_t data_int3 = ((data & ~0xff) | 0xcc);
    //cout<<"bug-debug> data at "<<bp_addr<<" is "<<data_int3<<"\n";
    ptrace(PTRACE_POKEDATA, debugee_pid, bp_addr, data_int3);
    bp_enable = true;
}

void breakpoint::disable_bp(){
    auto data = ptrace(PTRACE_PEEKDATA, debugee_pid, bp_addr, nullptr);
    //replacing int3 with the original data
    uint64_t restr_data = ((data & ~0xff) | orig_data);
    ptrace(PTRACE_POKEDATA, debugee_pid, bp_addr, restr_data);
    bp_enable = false;
}

class debugger{
    private:
        string debugee_name;
        pid_t debugee_pid;
        unordered_map<intptr_t, breakpoint> bp_map;
        dwarf::dwarf prog_dwarf;
        elf::elf prog_elf;
        uint64_t load_addr;
        void getCommand(const string &cmdline);
        bool isCommandOK(string& s, string cmd){
            if(s.size() > cmd.size()) return false;
            return equal(s.begin(), s.end(), cmd.begin());
        }
        void continue_exec();
        void sig_wait();
        

    public:
        debugger(string name, pid_t pid){
            debugee_name = name;
            debugee_pid = pid;
            auto fd = open(name.c_str(), O_RDONLY);
            prog_elf = elf::elf{elf::create_mmap_loader(fd)};
            prog_dwarf = dwarf::dwarf{dwarf::elf::create_loader(prog_elf)};
        }
        void run();
        void set_bp_addr(intptr_t addr);
        uint64_t read_mem(intptr_t addr){
            return ptrace(PTRACE_PEEKDATA, debugee_pid, addr, nullptr);
        }
        void write_mem(intptr_t addr, uint64_t value){
            ptrace(PTRACE_POKEDATA, debugee_pid, addr, value);
        }
        uint64_t get_pc();
        void set_pc(uint64_t pc);
        void bp_step_over();
        dwarf::die get_func_pc(uint64_t pc);
        dwarf::line_table::iterator get_line_pc(uint64_t pc);
        void init_load_addr();
        void print_curr_line(string file_name, unsigned int line_no);
        void sigtrap_handler(siginfo_t info);
        void single_stepi();
        void single_stepi_bp();
        void step_out();
        void step_in();
        void step_over();
        void rm_bp(intptr_t addr);
        void set_bp_func(string name);
        void set_bp_source(string &file, unsigned int line);
        void backtrace();
        void variables();
};

void debugger::variables(){
    auto func = get_func_pc(get_pc() - load_addr);
    uint64_t val;
    for(auto& die : func){
        if(die.tag == dwarf::DW_TAG::variable){
            auto loc = die[dwarf::DW_AT::location];
            if(loc.get_type() == dwarf::value::type::exprloc){
                ptrace_expr_context c(debugee_pid, load_addr);
                auto res = loc.as_exprloc().evaluate(&c);
                switch(res.location_type){
                    case dwarf::expr_result::type::address:
                    {
                        auto offset = res.value;
                        val = read_mem(offset);
                        cout<<"| "<<at_name(die)<<" | addr: (0x "<<hex<<offset<<" ) | val = "<<val<<"\n";
                        break;
                    }
                    case dwarf::expr_result::type::reg:
                    {                
                        val = get_reg_val_dwarf(debugee_pid, res.value);
                        cout<<"| "<<at_name(die)<<" | reg: ( "<<res.value<<" ) | val = "<<val<<"\n";
                        break;
                    }
                    default:
                        throw runtime_error{"Unhandled variable loc!\n"};
                }
            }
            else{
                throw runtime_error{"Unhandled variable loc!\n"};
            }
        }
    }
}

void debugger::sig_wait(){
    int status;
    waitpid(debugee_pid, &status, 0);

    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, debugee_pid, nullptr, &info);

    switch(info.si_signo){
        case SIGTRAP:
            sigtrap_handler(info);
            break;
        case SIGSEGV:
            cout<<"SEGMENTATION FAULT! (code: "<<info.si_code<<"\n";
            break;
        default:
            cout<<"Signal: "<<strsignal(info.si_signo)<<endl;
    }
}

void debugger::sigtrap_handler(siginfo_t info){
    switch(info.si_code){
        case SI_KERNEL:
        case TRAP_BRKPT:
        {
            set_pc(get_pc() - 1);
            cout<<"Breakpoint hit at address 0x"<<hex<<get_pc()<<endl;
            uint64_t offset_pc = get_pc() - load_addr;
            //cout<<offset_pc<<endl;
            auto line_entry = get_line_pc(offset_pc);
            print_curr_line(line_entry->file->path, line_entry->line);
            break;
        }
        case TRAP_TRACE:
            break;
    }
}

void debugger::single_stepi(){
    ptrace(PTRACE_SINGLESTEP, debugee_pid, nullptr, nullptr);
    sig_wait();
}

void debugger::single_stepi_bp(){
    if(bp_map.count(get_pc())){
        bp_step_over();
    }
    else{
        single_stepi();
    }
}

void debugger::step_out(){
    uint64_t fptr = get_reg_val(debugee_pid, reg::rbp);
    uint64_t ret_addr = read_mem(fptr+8);

    bool bp_remove = false;
    if(!bp_map.count(ret_addr)){
        set_bp_addr(ret_addr);
        bp_remove = true;
    }

    continue_exec();

    if(bp_remove){
        rm_bp(ret_addr);
    }
}

void debugger::rm_bp(intptr_t addr){
    if(bp_map.at(addr).is_enabled()){
        bp_map.at(addr).disable_bp();
    }

    bp_map.erase(addr);
}

void debugger::step_in(){
    uint64_t offset_pc = get_pc() - load_addr;
    auto line_no = get_line_pc(offset_pc)->line;
    while(get_line_pc(get_pc() - load_addr)->line == line_no) {
        single_stepi_bp();
    }

    auto line = get_line_pc(get_pc() - load_addr);
    print_curr_line(line->file->path, line->line);
}

void debugger::step_over(){
    uint64_t offset = get_pc() - load_addr;
    auto func = get_func_pc(offset);

    dwarf::taddr low_pc = at_low_pc(func);
    dwarf::taddr high_pc = at_high_pc(func);

    auto line = get_line_pc(low_pc);
    auto start = get_line_pc(offset);
    vector<intptr_t> temp_bp;
    while(line->address < high_pc){
        auto ld_addr = line->address + load_addr;
        if(line->address != start->address && !bp_map.count(ld_addr)){
            set_bp_addr(ld_addr);
            temp_bp.push_back(ld_addr);
        }
        line++;
    }

    uint64_t fptr = get_reg_val(debugee_pid, reg::rbp);
    uint64_t ret_addr = read_mem(fptr);
    if(!bp_map.count(ret_addr)){
        set_bp_addr(ret_addr);
        temp_bp.push_back(ret_addr);
    }

    continue_exec();

    for(auto del_addr : temp_bp)
        rm_bp(del_addr);
}

void debugger::set_bp_func(string name){
    for(auto& comp_u : prog_dwarf.compilation_units()){
        for(auto& die : comp_u.root()){
            if(die.has(dwarf::DW_AT::name) && at_name(die) == name){
                dwarf::taddr low_pc = at_low_pc(die);
                auto line = get_line_pc(low_pc);
                line++;
                set_bp_addr(line->address + load_addr);
            }
        }
    }
}

bool is_file_name(string& s, const string& path){
    if(s.size() > path.size()){
        return false;
    }
    return std::equal(s.begin(), s.end(), path.begin() + path.size() - s.size());
}

void debugger::set_bp_source(string& file, unsigned int line){
    for(auto& comp_u : prog_dwarf.compilation_units()){
        if(is_file_name(file, at_name(comp_u.root()))){
            auto& lt = comp_u.get_line_table();

            for(auto& entry : lt){
                if(entry.is_stmt && entry.line == line){
                    set_bp_addr(entry.address + load_addr);
                    return;
                }
            }
        }
    }
}

void debugger::backtrace(){
    auto output_format = [frame_no = 0](auto&& func) mutable {
        cout<<"| Frame #"<<frame_no++<<" | 0x"<<dwarf::at_low_pc(func)<<" "<<dwarf::at_name(func)<<"\n";
    };

    auto curr_func = get_func_pc(get_pc() - load_addr);
    output_format(curr_func);
    uint64_t fptr = get_reg_val(debugee_pid, reg::rbp);
    uint64_t ret_addr = read_mem(fptr+8);

    while(dwarf::at_name(curr_func) != "main"){
        curr_func = get_func_pc(ret_addr - load_addr);
        output_format(curr_func);
        fptr = read_mem(fptr);
        ret_addr = read_mem(fptr+8);
    }
}

void debugger::getCommand(const string &cmdline){
    vector<string> split_args;
    stringstream ss(cmdline);
    string word;
    while(ss >> word){
        split_args.push_back(word);
    }

    string command = split_args[0];
    if(isCommandOK(command, "continue")){ //allows "cont" and "c" as well
        continue_exec();
    }
    else if(isCommandOK(command, "break")){
        if(split_args[1][0] == '*'){
            string temp_addr = split_args[1];
            string addr;
            addr.assign(temp_addr, 3, temp_addr.length());
            set_bp_addr(stol(addr, 0, 16));
        }
        else if(split_args[1].find(':') != string::npos){
            vector<string> split_fileline;
            stringstream fl(split_args[1]);
            string str;
            while(getline(fl, str, ':')){
                split_fileline.push_back(str);
            }
            set_bp_source(split_fileline[0], stol(split_fileline[1]));
        }
        else{
            set_bp_func(split_args[1]);
        }
    }
    else if(isCommandOK(command, "memory")){
        string temp_addr = split_args[2];
        string addr;
        addr.assign(temp_addr, 3, temp_addr.length());
        if(isCommandOK(split_args[1], "read")){
            cout<<hex<<read_mem(stol(addr, 0, 16))<<endl;
        }
        else if(isCommandOK(split_args[1], "write")){
            string write_data {split_args[3], 2};
            write_mem(stol(addr, 0, 16), stol(write_data, 0, 16));
        }
    }
    else if(isCommandOK(command, "register")){
        if(isCommandOK(split_args[1], "read")){
            cout<<hex<<get_reg_val(debugee_pid, get_reg_name(split_args[2]))<<endl;
        }
        else if(isCommandOK(split_args[1], "write")){
            string write_data {split_args[3], 2};
            set_reg_val(debugee_pid, get_reg_name(split_args[2]), stol(write_data, 0, 16));
        }
    }
    else if(isCommandOK(command, "step")){
        step_in();
    }
    else if(isCommandOK(command, "over")){
        step_over();
    }
    else if(isCommandOK(command, "finish")){
        step_out();
    }
    else if(isCommandOK(command, "quit") || command == "exit"){
        exit(0);
    }
    else if(isCommandOK(command, "backtrace")){
        backtrace();
    }
    else if(isCommandOK(command, "variables")){
        variables();
    }
    else{
        cerr<<"UNKNOWN COMMAND!\n";
    }

}

void debugger::continue_exec(){
    bp_step_over();
    ptrace(PTRACE_CONT, debugee_pid, nullptr, nullptr);

    sig_wait();
}

void debugger::run(){
    
    sig_wait();
    init_load_addr();
    //cout<<"HELLO\n";

    char* cmdline;
    while((cmdline = linenoise("bug-debug> ")) != nullptr){
        getCommand(cmdline);
        linenoiseHistoryAdd(cmdline);
        linenoiseFree(cmdline);
    }
}

uint64_t debugger::get_pc(){
    return get_reg_val(debugee_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc){
    set_reg_val(debugee_pid, reg::rip, pc);
}

void debugger::bp_step_over(){
    if(bp_map.count(get_pc())){
        auto& bp = bp_map[get_pc()];
        if(bp.is_enabled()){
            bp.disable_bp();
            ptrace(PTRACE_SINGLESTEP, debugee_pid, nullptr, nullptr);
            sig_wait();
            bp.enable_bp();
        }
    }
}

void debugger::set_bp_addr(intptr_t addr){
    cout<<"Breakpoint set at address 0x"<<hex<<addr<<"\n";
    breakpoint bp(debugee_pid, addr);
    bp.enable_bp();
    bp_map[addr] = bp;
}

dwarf::die debugger::get_func_pc(uint64_t pc){
    for(auto &comp_u : prog_dwarf.compilation_units()){
        if(die_pc_range(comp_u.root()).contains(pc)){
            for(auto &die : comp_u.root()){
                if(die.tag == dwarf::DW_TAG::subprogram){
                    if(die_pc_range(die).contains(pc)){
                        return die;
                    }
                }
            }
        }
    }
    throw out_of_range("Cannot find function\n");
}

dwarf::line_table::iterator debugger::get_line_pc(uint64_t pc){
    for(auto &comp_u : prog_dwarf.compilation_units()){
        //cout<<"hi"<<"\n";
        if(die_pc_range(comp_u.root()).contains(pc)){
            auto &lt = comp_u.get_line_table();
            auto it = lt.find_address(pc);
            if(it == lt.end()){
                throw out_of_range("1Line entry not found!\n");
            }
            else
                return it;
        }
    }
    throw out_of_range("2Line entry not found!\n");
}

void debugger::init_load_addr(){
    //cout<<"HELLO\n";
    ifstream fd("/proc/" + std::to_string(debugee_pid) + "/maps");
        
    string addr;
    getline(fd, addr, '-');
    load_addr = stoll(addr, 0 ,16);
}

void debugger::print_curr_line(string file_name, unsigned int line_no){
    ifstream file{file_name};

    unsigned int curr_line = 0;
    string str;
    while(getline(file, str)){
        curr_line++;
        if(curr_line == line_no){
            cout<<"> At line "<<(long)line_no<<": "<<str;
        }
    }
    cout<<endl;
}

void debugee(char* prog_name){
    if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
        cerr<<"ptrace ERROR!\n";
        return;
    }

    execl(prog_name, prog_name, nullptr);
}

int main(int argc, char* argv[]){
    if(argc < 2){
        cerr<<"Specify program name\n";
        return -1;
    }

    char* prog = argv[1];
    auto pid = fork();

    if(pid == 0){
        personality(ADDR_NO_RANDOMIZE);
        debugee(prog);
    }

    else if(pid >= 1){
        cout<<"Debugging process "<<pid<<"...\n";
        debugger dbg(prog, pid);
        dbg.run();
    }

}