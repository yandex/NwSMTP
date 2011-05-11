#if !defined(_PIDFILE_H_)
#define _PIDFILE_H_

#include <string>

struct pid_file
{
    bool create(const std::string& _file_name);

    bool unlink();

    std::string m_pid_file_name;
};

extern pid_file g_pid_file;

#endif
