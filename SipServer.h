#ifndef SIPSERVER_H
#define SIPSERVER_H

extern "C" {
#include <eXosip2/eXosip.h>
}

#include <string>
#include <map>
#include <vector>
#include <set>
#include <chrono>
#include <mutex>
#include <thread>
#include <functional>

// 服务器配置信息类
class server_info {
public:
    server_info(const char* ua, const char* nonce, const char* ip, int port, int rtp_port,
                const char* sip_id, const char* sip_realm, const char* sip_pass, int sip_timeout,
                int sip_expiry);
    ~server_info() = default;

    [[nodiscard]] auto get_ua() const -> const char*;
    [[nodiscard]] auto get_nonce() const -> const char*;
    [[nodiscard]] auto get_ip() const -> const char*;
    [[nodiscard]] auto get_port() const -> int;
    [[nodiscard]] auto get_rtp_port() const -> int;
    [[nodiscard]] auto get_sip_id() const -> const char*;
    [[nodiscard]] auto get_sip_realm() const -> const char*;
    [[nodiscard]] auto get_sip_pass() const -> const char*;
    [[nodiscard]] auto get_timeout() const -> int;
    [[nodiscard]] auto get_expiry() const -> int;

private:
    const char* m_ua_;
    const char* m_nonce_;
    const char* m_ip_;
    int m_port_;
    const char* m_sip_id_;
    const char* m_sip_realm_;
    const char* m_sip_pass_;
    int m_sip_timeout_;
    int m_sip_expiry_;
    int m_rtp_port_;
};

// 客户端信息类
class client {
public:
    client(const char* ip, int port, const char* device);
    ~client() = default;

    auto set_rtp_port(int rtp_port) -> void;
    auto set_reg(bool is_reg) -> void;

    [[nodiscard]] auto get_device() const -> const char*;
    [[nodiscard]] auto get_ip() const -> const char*;
    [[nodiscard]] auto get_port() const -> int;
    [[nodiscard]] auto is_registered() const -> bool;

private:
    const char* m_ip_;
    int m_port_;
    const char* m_device_;
    bool m_is_reg_;
    int m_rtp_port_{};
};

// 设备类型枚举
enum class device_type {
    unknown = 0,
    camera = 1,         // 摄像头
    nvr = 2,           // 录像机
    audio_out = 3,     // 音频输出
    alarm = 4,         // 报警设备
    platform = 5       // 平台设备
};

// 设备信息结构
struct device_info {
    std::string device_id;
    std::string name;
    std::string manufacturer;
    std::string model;
    std::string status;
    std::string address;
    device_type type;
    std::string parent_device_id;  // 父设备ID
    std::string parent_ip;         // 父设备IP（用于发送消息）
    int parent_port;               // 父设备端口
    std::vector<device_info> children; // 子设备列表

    // 构造函数
    device_info() : type(device_type::unknown), parent_port(0) {}
};

// PTZ控制命令枚举
enum class ptz_command {
    ptz_up = 0,
    ptz_down,
    ptz_left,
    ptz_right,
    ptz_zoom_in,
    ptz_zoom_out,
    ptz_stop
};

// 预置位操作枚举
enum class preset_operation {
    set,     // 设置预置位
    call,    // 调用预置位
    remove   // 删除预置位
};

// 录像信息结构
struct record_info {
    std::string device_id;
    std::string start_time;
    std::string end_time;
    std::string name;
    std::string file_path;
    std::string address;
    uint64_t file_size;
    std::string recorder_id;
    std::string type;
};

// 回放控制命令枚举
enum class playback_control {
    play,     // 播放
    pause,    // 暂停
    stop,     // 停止
    speed,    // 倍速播放
    seek      // 跳转
};

// 回放会话结构
struct playback_session {
    std::string session_id;
    std::string device_id;
    int call_id;
    int dialog_id;
    std::string start_time;
    std::string end_time;
    std::string ssrc;
    int rtp_port;
    bool is_playing;
    std::chrono::steady_clock::time_point last_activity;
};

// 下载状态枚举
enum class download_status {
    pending,      // 等待中
    downloading,  // 下载中
    completed,    // 完成
    failed,       // 失败
    cancelled     // 取消
};

// 下载方法枚举
enum class download_method {
    http,    // HTTP下载
    ftp,     // FTP下载
    direct   // 直接传输
};

// 下载会话结构
struct download_session {
    std::string session_id;
    std::string device_id;
    std::string file_name;
    std::string file_path;
    std::string local_save_path;
    std::string download_url;
    download_method method{};
    download_status status{};
    uint64_t file_size{};
    uint64_t downloaded_size{};
    std::string start_time;
    std::string end_time;
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::steady_clock::time_point start_download_time;
    std::unique_ptr<std::thread> download_thread;
    std::function<void(const download_session&)> progress_callback;

    // 移动语义支持
    download_session() = default;
    download_session(const download_session&) = delete;
    auto operator=(const download_session&) -> download_session& = delete;
    download_session(download_session&&) = default;
    auto operator=(download_session&&) -> download_session& = default;
};

// 抓拍状态枚举
enum class snapshot_status {
    pending,    // 等待中
    capturing,  // 抓拍中
    completed,  // 完成
    failed      // 失败
};

// 抓拍会话结构
struct snapshot_session {
    std::string session_id;
    std::string device_id;
    std::string image_name;
    std::string image_path;
    std::string local_save_path;
    snapshot_status status{};
    uint32_t quality{};
    std::string format;
    std::chrono::steady_clock::time_point request_time;
    std::chrono::steady_clock::time_point last_activity;
};

// 设备配置类型枚举
enum class device_config_type {
    basic_param,   // 基本参数
    video_param,   // 视频参数
    audio_param,   // 音频参数
    network_param, // 网络参数
    ptz_param,     // 云台参数
    record_param,  // 录像参数
    alarm_param    // 报警参数
};

// 设备配置结构
struct device_config {
    std::string device_id;
    device_config_type config_type{};
    std::string config_data;
    std::chrono::steady_clock::time_point last_update;
};

// 通知消息结构
struct notify_message {
    std::string device_id;
    std::string notify_type;
    std::string content;
    std::chrono::steady_clock::time_point receive_time;
};

// SIP服务器主类
class sip_server {
public:
    explicit sip_server(server_info* info);
    ~sip_server();

    // 服务器控制接口
    auto start() -> int;                    // 启动服务器
    auto stop() -> void;                    // 停止服务器
    auto is_running() const -> bool;        // 检查运行状态

    // 设备管理接口
    auto get_registered_devices() const -> std::vector<std::string>;       // 获取已注册设备列表
    auto get_device_info(const char* device_id) const -> device_info;      // 获取设备信息
    auto is_device_online(const char* device_id) const -> bool;            // 检查设备在线状态
    auto get_all_camera_devices() const -> std::vector<device_info>;       // 获取所有摄像头设备（包含层次结构）
    auto find_device_in_tree(const char* device_id) const -> device_info*; // 在设备树中查找设备
    auto get_device_parent_info(const char* device_id) const -> std::pair<std::string, int>; // 获取设备父级IP和端口

    // 设备目录接口
    auto request_catalog(const char* device_id) const -> int;                    // 请求设备目录
    auto get_device_catalog(const char* device_id) const -> std::vector<device_info>; // 获取设备目录

    // PTZ控制接口
    auto send_ptz_control(const char* device_id, ptz_command cmd, int speed) const -> int;          // 发送PTZ控制命令
    auto send_preset_control(const char* device_id, preset_operation op, int preset_id) const -> int; // 发送预置位控制
    auto send_ptz_position_query(const char* device_id) const -> int;            // 查询PTZ位置

    // 录像管理接口
    auto request_record_query(const char* device_id, const char* start_time,
                              const char* end_time, const char* type = "all") const -> int;     // 查询录像
    auto get_record_list(const char* device_id) const -> std::vector<record_info>;       // 获取录像列表

    // 回放控制接口
    auto start_playback(const char* device_id, const char* start_time, const char* end_time) -> std::string; // 开始回放
    auto control_playback(const char* session_id, playback_control control, const char* param = nullptr) -> int; // 控制回放
    auto stop_playback(const char* session_id) -> int;                     // 停止回放
    auto get_playback_sessions() const -> std::vector<std::string>;        // 获取回放会话列表

    // 文件下载接口
    auto request_file_download(const char* device_id, const char* start_time,
                               const char* end_time, const char* local_path = nullptr) -> std::string; // 请求文件下载
    auto cancel_download(const char* session_id) -> int;                   // 取消下载
    auto get_download_progress(const char* session_id) const -> std::pair<uint64_t, uint64_t>; // 获取下载进度
    auto get_download_status(const char* session_id) const -> download_status;     // 获取下载状态
    auto list_downloads() const -> std::vector<std::string>;               // 列出所有下载会话
    auto set_download_root_path(const char* path) -> void;                 // 设置下载根目录

    // 抓拍接口
    auto request_snapshot(const char* device_id, uint32_t quality = 80,
                          const char* format = "JPEG", const char* local_path = nullptr) -> std::string; // 请求抓拍
    auto get_snapshot_status(const char* session_id) const -> snapshot_status;     // 获取抓拍状态
    auto list_snapshots() const -> std::vector<std::string>;               // 列出抓拍会话
    auto set_snapshot_root_path(const char* path) -> void;                 // 设置抓拍根目录

    // 设备配置接口
    auto request_device_config(const char* device_id, device_config_type config_type) const -> int; // 请求设备配置
    auto set_device_config(const char* device_id, device_config_type config_type,
                           const char* config_xml) const -> int;                  // 设置设备配置
    auto get_device_config(const char* device_id, device_config_type config_type) const -> std::string; // 获取设备配置

    // 通知消息接口
    auto get_notify_messages(const char* device_id = nullptr) const -> std::vector<notify_message>; // 获取通知消息
    auto clear_notify_messages() -> void;                                  // 清空通知消息

    //调试和辅助方法
    auto debug_record_memory(const std::string& device_id) const -> void;
    auto test_capability_query(const char* device_id) const -> void;
    auto ptz_position_find(const char* device_id) const -> void;
    auto test_ptz_operations(const char* device_id) const -> int;
    auto test_recording_operations(const char* device_id) -> int;

private:
    // SIP协议处理
    auto init_sip_server() -> int;
    auto sip_event_handle(const eXosip_event_t* evtp) -> void;
    auto loop() -> void;  // 移到private，由start()方法调用

    // SIP消息处理
    auto response_message_answer(const eXosip_event_t* evtp, int code) const -> void;
    auto response_register(const eXosip_event_t* evtp) -> void;
    auto response_register_401_unauthorized(const eXosip_event_t* evtp) const -> void;
    auto response_message(const eXosip_event_t* evtp) -> void;
    auto response_invite_ack(const eXosip_event_t* evtp) const -> void;
    auto request_bye(const eXosip_event_t* evtp) const -> int;
    auto request_invite(const char* device, const char* user_ip, long user_port) const -> int;

    // 工具方法
    static auto parse_xml(const char* src, const char* start_tag, const char* end_tag,
                          char* dest, long dest_size) -> int;
    static auto dump_request(const eXosip_event_t* evtp) -> void;
    static auto dump_response(const eXosip_event_t* evtp) -> void;
    auto send_sip_message(const char* device, const char* content) const -> int;
    auto get_client_by_device(const char* device) const -> client*;
    auto clear_client_map() -> void;

    // 解析处理方法
    auto parse_catalog_response(const char* xml) -> void;
    auto parse_record_info_response(const char* xml) -> void;
    auto parse_download_info_response(const char* xml) -> void;
    auto parse_snapshot_response(const char* xml) -> void;
    auto parse_device_config_response(const char* xml) -> void;
    auto parse_notify_content(const char* xml) -> void;

    // 事件处理方法
    static auto handle_download_response(const eXosip_event_t* evtp) -> void;
    static auto handle_playback_info(const eXosip_event_t* evtp) -> void;
    auto handle_snapshot_notify(const eXosip_event_t* evtp) -> void;
    auto handle_device_config_notify(const eXosip_event_t* evtp) -> void;
    auto handle_notify_message(const eXosip_event_t* evtp) -> void;

    // 下载相关私有方法
    auto request_download_info(const char* device_id, const char* start_time, const char* end_time) const -> int;
    auto start_file_download(const download_session& session) -> void;
    auto download_file_http(download_session& session) -> bool;
    auto download_file_ftp(download_session& session) -> bool;
    auto update_download_progress(const std::string& session_id, uint64_t downloaded) -> void;
    auto complete_download(const std::string& session_id, bool success) -> void;
    static auto generate_download_session_id() -> std::string;

    // 回放相关私有方法
    auto request_playback_invite(const char* device_id, const char* start_time, const char* end_time) const -> int;
    auto send_playback_control(const char* device_id, const char* session_id, playback_control control,
                               const char* range = nullptr, const char* scale = nullptr) const -> int;
    auto build_playback_sdp(const char* device_id, const char* start_time,
                            const char* end_time, const char* ssrc) const -> std::string;
    static auto generate_ssrc() -> std::string;

    // 抓拍相关私有方法
    static auto generate_snapshot_session_id() -> std::string;

    // 配置相关私有方法
    static auto device_config_type_to_string(device_config_type type) -> std::string;

    // PTZ相关私有方法
    static auto build_preset_cmd(preset_operation op, int preset_id) -> std::string;

    // 清理方法
    auto cleanup_expired_sessions() -> void;
    auto cleanup_expired_queries() const -> void;
    auto cleanup_expired_downloads() -> void;
    auto cleanup_expired_snapshots() -> void;
    auto request_next_record_page(const std::string& device_id) const -> int;

    // 成员变量
    bool m_quit_;
    bool m_running_;
    eXosip_t* m_sip_ctx_;
    server_info* m_info_;
    std::unique_ptr<std::thread> m_server_thread_;

    // 客户端管理
    std::map<std::string, client*> m_client_map_;
    std::set<client*> clients_set_;

    // 设备信息
    std::map<std::string, std::vector<device_info>> m_device_catalogs_;
    std::map<std::string, device_info> m_device_tree_;          // 层次化设备树：device_id -> device_info
    std::set<std::string> m_camera_device_ids_;                 // 摄像头设备ID集合

    // 录像管理
    std::map<std::string, std::vector<record_info>> m_record_map_;
    std::map<std::string, playback_session> m_playback_sessions_;

    // 下载管理
    std::map<std::string, download_session> m_download_sessions_;
    mutable std::mutex m_download_mutex_;
    std::string m_download_root_path_;

    // 抓拍管理
    std::map<std::string, snapshot_session> m_snapshot_sessions_;
    mutable std::mutex m_snapshot_mutex_;
    std::string m_snapshot_root_path_;

    // 配置管理
    std::map<std::string, device_config> m_device_configs_;
    mutable std::mutex m_config_mutex_;

    // 通知消息管理
    std::vector<notify_message> m_notify_messages_;
    mutable std::mutex m_notify_mutex_;

    // 查询状态管理
    struct record_query_state {
        std::string device_id;
        std::string start_time;
        std::string end_time;
        std::string query_type = "all";
        int expected_total = 0;
        int received_count = 0;
        bool query_complete = false;
        bool playback_initiated = false;
        std::chrono::steady_clock::time_point last_query_time;
        long last_sn = 0;
    };
    mutable std::map<std::string, record_query_state> m_pending_queries_;
    mutable std::mutex m_query_mutex_;

    // 清理管理
    std::chrono::steady_clock::time_point m_last_cleanup_ = std::chrono::steady_clock::now();
    static constexpr int cleanup_interval_seconds = 300;

    int m_next_playback_port_ = 20000;
};

#endif // SIPSERVER_H