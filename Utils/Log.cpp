//
// Created by root on 25-9-25.
//
#include "Log.h"
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <memory>

// 全局日志级别
LogLevel g_log_level = LogLevel::INFO;

// 日志文件指针
static FILE* g_log_file = nullptr;

// 日志互斥锁
static std::mutex g_log_mutex;

// 日志级别字符串
static const char* level_strings[] = {
    "DEBUG", "INFO", "WARN", "ERROR"
};

// 日志级别颜色（ANSI颜色代码）
static const char* level_colors[] = {
    "\033[36m", // DEBUG - 青色
    "\033[32m", // INFO - 绿色
    "\033[33m", // WARN - 黄色
    "\033[31m" // ERROR - 红色
};

static const char* color_reset = "\033[0m";

void log_output(LogLevel level, const char* file, int line, const char* func, const char* fmt, ...) {
    // 检查日志级别
    if (level < g_log_level) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_log_mutex);

    // 获取当前时间
    time_t now = time(nullptr);
    struct tm* tm_info = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    // 是否输出到控制台（带颜色）
    bool output_to_console = (g_log_file == nullptr);

    // 格式化用户消息
    va_list args;
    va_start(args, fmt);

    char message[1024];
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    // 构造完整的日志消息
    char full_message[1536];
    snprintf(full_message, sizeof(full_message), "[%s] [%s] %s:%d %s() - %s",
             time_str, level_strings[static_cast<int>(level)], file, line, func, message);

    if (output_to_console) {
        // 输出到控制台（带颜色）
        printf("%s%s%s\n",
               level_colors[static_cast<int>(level)],
               full_message,
               color_reset);
        fflush(stdout);
    }
    else {
        // 输出到文件（不带颜色）
        fprintf(g_log_file, "%s\n", full_message);
        fflush(g_log_file);
    }
}

void set_log_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_level = level;
}

void set_log_file(const char* filename) {
    if (!filename) return;

    std::lock_guard<std::mutex> lock(g_log_mutex);

    // 关闭现有文件
    if (g_log_file && g_log_file != stdout) {
        fclose(g_log_file);
        g_log_file = nullptr;
    }

    // 打开新文件
    g_log_file = fopen(filename, "a");
    if (!g_log_file) {
        // 如果打开失败，回退到控制台输出
        fprintf(stderr, "Failed to open log file: %s, falling back to console\n", filename);
        g_log_file = nullptr;
    }
}

void close_log_file() {
    std::lock_guard<std::mutex> lock(g_log_mutex);

    if (g_log_file && g_log_file != stdout) {
        fclose(g_log_file);
        g_log_file = nullptr;
    }
}

void log_init() {
    // 初始化时可以设置默认配置
    g_log_level = LogLevel::INFO;
    g_log_file = nullptr;

    // 输出初始化信息
    LOGI("日志系统初始化完成");
}

void log_cleanup() {
    LOGI("日志系统清理");
    close_log_file();
}
