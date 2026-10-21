#include "log.h"

#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>

extern "C" void audit_native_probe(const char* tag, const char* probe_type, const char* detail) {
    if (!tag || !probe_type || !detail) return;

    struct timeval tv;
    gettimeofday(&tv, nullptr);
    struct tm tm_buf;
    localtime_r(&tv.tv_sec, &tm_buf);

    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    pid_t pid = getpid();
    pid_t tid = gettid();

    char buf[1024];
    int len = snprintf(buf, sizeof(buf),
        "[%s.%03d][native pid:%d tid:%d][NativeProbe] [%s] %s | %s\n",
        time_str, (int)(tv.tv_usec / 1000), pid, tid, tag, probe_type, detail);

    if (len <= 0) return;

    // 1. Append to primary internal security environment log
    const char* path_primary = "/data/user/0/com.tencent.mobileqq/files/security_environment_audit.log";
    int fd = open(path_primary, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }

    // 2. Also append to primary all-events report_audit.log
    const char* path_all = "/data/user/0/com.tencent.mobileqq/files/report_audit.log";
    int fd_all = open(path_all, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd_all >= 0) {
        write(fd_all, buf, len);
        close(fd_all);
    }

    // 3. Try external files dir if accessible
    const char* path_sec_ext = "/storage/emulated/0/Android/data/com.tencent.mobileqq/files/security_environment_audit.log";
    int fd_ext = open(path_sec_ext, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd_ext >= 0) {
        write(fd_ext, buf, len);
        close(fd_ext);
    }
}
