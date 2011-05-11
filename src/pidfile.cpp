#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fstream>

#include "pidfile.h"

pid_file g_pid_file;

bool pid_file::create(const std::string& _file_name)
{

    if (_file_name.empty())
    {
        return false;
    }

    m_pid_file_name = _file_name;

    std::ofstream s(m_pid_file_name.c_str());

    s << getpid() << std::endl;

    return s.good();
}

bool pid_file::unlink()
{
    if (!m_pid_file_name.empty())
    {
        return ::unlink(m_pid_file_name.c_str());
    }

    return false;
}
