/*
bug-debug: simple debugger
Author: Sudarshan Sundarrajan
*/


#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include "linenoise.h"
#include <sstream>
#include <unordered_map>
#include <sys/personality.h>

using namespace std;

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
};

void breakpoint::enable_bp(){
    auto data = ptrace(PTRACE_PEEKDATA, debugee_pid, bp_addr, nullptr);
    orig_data = (uint8_t)(data & 0xff);
    uint64_t data_int3 = ((data & ~0xff) | 0xcc);
    ptrace(PTRACE_POKEDATA, debugee_pid, bp_addr, data_int3);
    bp_enable = true;
}

void breakpoint::disable_bp(){
    auto data = ptrace(PTRACE_PEEKDATA, debugee_pid, bp_enable, nullptr);
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
        void getCommand(const string &cmdline);
        bool isCommandOK(string& s, string cmd){
            if(s.size() > cmd.size()) return false;
            return equal(s.begin(), s.end(), cmd.begin());
        }
        void continue_exec();
        

    public:
        debugger(string name, pid_t pid){
            debugee_name = name;
            debugee_pid = pid;
        }
        void run();
        void set_bp_addr(intptr_t addr);
};

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
        string temp_addr = split_args[1];
        string addr;
        addr.assign(temp_addr, 3, temp_addr.length());
        set_bp_addr(stol(addr, 0, 16));
    }
    else if(isCommandOK(command, "quit") || command == "exit"){
        exit(0);
    }
    else{
        cerr<<"UNKNOWN COMMAND!\n";
    }

}

void debugger::continue_exec(){
    ptrace(PTRACE_CONT, debugee_pid, nullptr, nullptr);

    int status;
    waitpid(debugee_pid, &status, 0);
}

void debugger::run(){
    int status;
    waitpid(debugee_pid, &status, 0);

    char* cmdline;
    while((cmdline = linenoise("bug-debug> ")) != nullptr){
        getCommand(cmdline);
        linenoiseHistoryAdd(cmdline);
        linenoiseFree(cmdline);
    }
}

void debugger::set_bp_addr(intptr_t addr){
    cout<<"Breakpoint set at address 0x"<<hex<<addr<<"\n";
    breakpoint bp(debugee_pid, addr);
    bp.enable_bp();
    bp_map[addr] = bp;
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