#ifndef UTILS_LOG_H
#define UTILS_LOG_H

#include <cstdio>
#include <ctime>
#include <cstring>

// 日志级别定义
enum class LogLevel {
    DEBUG = 0,
    INFO,
    WARN,
    ERROR
};

// 全局日志级别设置
extern LogLevel g_log_level;

// 日志输出函数
void log_output(LogLevel level, const char* file, int line, const char* func, const char* fmt, ...);

// 获取文件名（不含路径）
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : \
(strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__))

// 日志宏定义
#ifdef DEBUG
#define LOGD(fmt, ...) log_output(LogLevel::DEBUG, __FILENAME__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#else
#define LOGD(fmt, ...)
#endif

#define LOGI(fmt, ...) log_output(LogLevel::INFO, __FILENAME__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) log_output(LogLevel::WARN, __FILENAME__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) log_output(LogLevel::ERROR, __FILENAME__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

// 设置日志级别
void set_log_level(LogLevel level);

// 设置日志文件输出
void set_log_file(const char* filename);

// 关闭日志文件
void close_log_file();

// 日志初始化和清理
void log_init();
void log_cleanup();

#endif // UTILS_LOG_H
