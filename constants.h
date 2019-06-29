#include <string>
using namespace std;

enum CPUStates{
	S_USER = 1,
	S_NICE = 2,
	S_SYSTEM = 3,
	S_IDLE = 4,
	S_IOWAIT = 5,
	S_IRQ = 6,
	S_SOFTIRQ = 7,
	S_STEAL = 8,
	S_GUEST = 9,
	S_GUEST_NICE = 10
};

class Path{

public:
    static string basePath() {
        return "/proc/";
    }
    static string cmdPath(){
        return "/cmdline";
    }
    static string statusPath(){
        return "/status";
    }
    static string statPath(){
        return "stat";
    }
    static string upTimePath(){
        return "uptime";
    }
    static string memInfoPath(){
        return "meminfo";
    }
    static string versionPath(){
        return "version";
    }
};
