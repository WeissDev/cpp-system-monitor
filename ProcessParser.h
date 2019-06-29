#include <algorithm>
#include <iostream>
#include <math.h>
#include <thread>
#include <chrono>
#include <iterator>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"


using namespace std;

class ProcessParser{
private:
    std::ifstream stream;
    public:
    static string getCmd(string pid);
    static vector<string> getPidList();
    static std::string getVmSize(string pid);
    static std::string getCpuPercent(string pid);
    static long int getSysUpTime();
    static std::string getProcUpTime(string pid);
    static string getProcUser(string pid);
    static vector<string> getSysCpuPercent(string coreNumber = "");
    static float getSysRamPercent();
    static string getSysKernelVersion();
    static int getNumberOfCores();
    static int getTotalThreads();
    static int getTotalNumberOfProcesses();
    static int getNumberOfRunningProcesses();
    static string getOSName();
    static std::string PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2);
    static bool isPidExisting(string pid);
};

// TODO: Define all of the above functions below:
string ProcessParser::getCmd(string pid) {
    ifstream stream;
    Util::getStream((Path::basePath() + pid + Path::cmdPath()), stream);
    string line;
    getline(stream, line);
    return line;
}

vector<string> ProcessParser::getPidList() {
    DIR* dir;
    dir = opendir("/proc");
    if (dir == NULL)
        throw runtime_error(strerror(errno));

    vector<string> container;

    while (dirent* dirp = readdir(dir)) {
        if (dirp->d_type != DT_DIR)
            continue;
        // is every character of the dir name a digit
        if (all_of(dirp->d_name, dirp->d_name + strlen(dirp->d_name), [](char c) { return isdigit(c); }))
            container.push_back(dirp->d_name);
    }

    if (closedir(dir))
        throw runtime_error(strerror(errno));

    return container;
}

string ProcessParser::getVmSize(string pid) {
    ifstream stream;
    Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);
    string line;
    string name = "VmData";
    float result;
    while (getline(stream ,line)) {
        if (line.compare(0, name.size(),name) == 0) {
            // Matching line found
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            //conversion kB -> GB
            result = (stof(values[1])/float(1024*1024));
            break;
        }
    }
    return to_string(result);
}

string ProcessParser::getCpuPercent(string pid) {
    ifstream stream;
    Util::getStream((Path::basePath() + pid + "/" + Path::statPath()), stream);
    string line;
    float result;
    getline(stream, line);

    // Split line at whitespaces
    istringstream buf(line);
    istream_iterator<string> beg(buf), end;
    vector<string> values(beg, end);
    
    float utime = stof(ProcessParser::getProcUpTime(pid));
    float stime = stof(values[14]);
    float cutime = stof(values[15]);
    float cstime = stof(values[16]);
    float starttime = stof(values[21]);

    float uptime = ProcessParser::getSysUpTime();

    float freq = sysconf(_SC_CLK_TCK);

    float total_time = utime + stime + cutime + cstime;
    float seconds = uptime - (starttime / freq);
    result = 100.0 * ((total_time / freq) / seconds);
    return to_string(result);
}

long int ProcessParser::getSysUpTime() {
    ifstream stream;
    Util::getStream((Path::basePath() + Path::upTimePath()), stream);

    string line;
    getline(stream, line);
    // Split line at whitespaces
    istringstream buf(line);
    istream_iterator<string> beg(buf), end;
    vector<string> values(beg, end);

    long int result = stoi(values[0]);
    return result;
}

string ProcessParser::getProcUpTime(string pid) {
    ifstream stream;
    Util::getStream((Path::basePath() + pid + "/" + Path::statPath()), stream);

    string line;
    getline(stream, line);

    // Split line at whitespaces
    istringstream buf(line);
    istream_iterator<string> beg(buf), end;
    vector<string> values(beg, end);

    // Using sysconf to get clock ticks of the host machine
    return to_string(float(stof(values[13])/sysconf(_SC_CLK_TCK)));
}

string ProcessParser::getProcUser(string pid) {
    ifstream stream;
    Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);
    string line;
    string name = "Uid:";
    string result = "";
    while (getline(stream, line)) {
        if (line.compare(0, name.size(),name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result = values[1];
            break;
        }
    }
    stream.close();
    Util::getStream("/etc/passwd", stream);
    name = ("x:" + result);

    // Searching for name of the user with selected UID
    while (getline(stream, line)) {

        if (line.find(name) != string::npos) {
            result = line.substr(0, line.find(":"));
            return result;
        }
    }
    return "";
}

vector<string> ProcessParser::getSysCpuPercent(string coreNumber) {
    ifstream stream;
    Util::getStream((Path::basePath() + Path::statPath()), stream);
    string line;
    string name = "cpu" + coreNumber;

    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return values;
        }
    }
    // default empty vector
    return (vector<string>());
}

float ProcessParser::getSysRamPercent() {
    string memAvailable = "MemAvailable:";
    string memFree = "MemFree:";
    string buffers = "Buffers:";

    ifstream stream;
    Util::getStream((Path::basePath() + Path::memInfoPath()), stream);

    float total_memory = 0;
    float free_memory = 0;
    float num_buffers = 0;
    string line;

    while (getline(stream, line)) {
        if (total_memory != 0 && free_memory != 0)
            break;
        if (line.compare(0, memAvailable.size(), memAvailable) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            total_memory = stof(values[1]);
        }
        if (line.compare(0, memFree.size(), memFree) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            free_memory = stof(values[1]);
        }
        if (line.compare(0, buffers.size(), buffers) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            num_buffers = stof(values[1]);
        }
    }
    return 100.0 * (1 - (free_memory / (total_memory - num_buffers)));
}

string ProcessParser::getSysKernelVersion() {
    ifstream stream;
    Util::getStream((Path::basePath() + Path::versionPath()), stream);
    string line;
    string name = "Linux version ";
    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return values[2];
        }
    }
    return "";
}

string ProcessParser::getOSName() {
    ifstream stream;
    Util::getStream("/etc/os-release", stream);

    string name = "PRETTY NAME=";
    string line;
    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            size_t found = line.find("=");
            found++;
            string result = line.substr(found);
            result.erase(remove(result.begin(), result.end(), '"'), result.end());
            return result;
        }
    }
    return "";
}

float getSysActiveCpuTime(vector<string> values) {
    return (stof(values[S_USER]) +
            stof(values[S_NICE]) +
            stof(values[S_SYSTEM]) +
            stof(values[S_IRQ]) +
            stof(values[S_SOFTIRQ]) +
            stof(values[S_STEAL]) +
            stof(values[S_GUEST]) +
            stof(values[S_GUEST_NICE]));
}

float getSysIdleCpuTime(vector<string>values) {
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}


int ProcessParser::getNumberOfCores() {
    ifstream stream;
    Util::getStream((Path::basePath() + "cpuinfo"), stream);

    string name = "cpu cores";
    string line;
    while (getline(stream, line)) {
        // Check if current line is named cpu cores
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            return stoi(values[3]);
        }
    }
    return 0;
}

int ProcessParser::getTotalThreads() {
    ifstream stream;
    vector<string> pid_list = ProcessParser::getPidList();
    string name = "Threads:";
    string line;
    int result = 0;

    for (string pid : pid_list) {
        Util::getStream((Path::basePath() + pid + Path::statusPath()), stream);

        while (getline(stream, line)) {
            if (line.compare(0, name.size(), name) == 0) {
                istringstream buf(line);
                istream_iterator<string> beg(buf), end;
                vector<string> values(beg, end);
                result += stoi(values[1]);
                break;
            }
        }
    }

    return result;
}

int ProcessParser::getTotalNumberOfProcesses() {
    ifstream stream;
    Util::getStream((Path::basePath() + Path::statPath()), stream);
    string line;
    string name = "processes";
    int result = 0;
    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    return result;
}

int ProcessParser::getNumberOfRunningProcesses() {
    ifstream stream;
    Util::getStream((Path::basePath() + Path::statPath()), stream);
    string line;
    string name = "procs_running";
    int result = 0;
    while (getline(stream, line)) {
        if (line.compare(0, name.size(), name) == 0) {
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            result += stoi(values[1]);
            break;
        }
    }
    return result;
}

string ProcessParser::PrintCpuStats(vector<string> values1, vector<string>values2) {
    float activeTime = getSysActiveCpuTime(values2) - getSysActiveCpuTime(values1);
    float idleTime = getSysIdleCpuTime(values2) - getSysIdleCpuTime(values1);
    float totalTime = activeTime + idleTime;
    float result = 100.0 * (activeTime / totalTime);
    return to_string(result);
};

bool ProcessParser::isPidExisting(string pid) {
    vector<string> pidList = ProcessParser::getPidList();
    if(find(pidList.begin(), pidList.end(), pid) != pidList.end()) {
        return true;
    } else {
        return false;
    }
}
