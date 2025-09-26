#include "SipServer.h"

#ifndef WIN32
#include <arpa/inet.h>
#else
#include <WinSock2.h>
#endif

#include <string>
#include <cstdio>
#include <chrono>
#include <thread>
#include "Utils/Log.h"
#include <tinyxml2.h>
#include <iconv.h>
#include <algorithm>
#include <ranges>
#include <curl/curl.h>
#include <filesystem>
#include <fstream>

using namespace tinyxml2;

extern "C" {
#include "Utils/HTTPDigest.h"
}

// ========== server_info 实现 ==========
server_info::server_info(const char* ua, const char* nonce, const char* ip, const int port, const int rtp_port,
                         const char* sip_id, const char* sip_realm, const char* sip_pass, const int sip_timeout,
                         const int sip_expiry) :
    m_ua_(ua), m_nonce_(nonce), m_ip_(ip), m_port_(port), m_sip_id_(sip_id),
    m_sip_realm_(sip_realm), m_sip_pass_(sip_pass), m_sip_timeout_(sip_timeout),
    m_sip_expiry_(sip_expiry), m_rtp_port_(rtp_port) {}

auto server_info::get_ua() const -> const char* {
    return m_ua_;
}

auto server_info::get_nonce() const -> const char* {
    return m_nonce_;
}

auto server_info::get_ip() const -> const char* {
    return m_ip_;
}

auto server_info::get_port() const -> int {
    return m_port_;
}

auto server_info::get_rtp_port() const -> int {
    return m_rtp_port_;
}

auto server_info::get_sip_id() const -> const char* {
    return m_sip_id_;
}

auto server_info::get_sip_realm() const -> const char* {
    return m_sip_realm_;
}

auto server_info::get_sip_pass() const -> const char* {
    return m_sip_pass_;
}

auto server_info::get_timeout() const -> int {
    return m_sip_timeout_;
}

auto server_info::get_expiry() const -> int {
    return m_sip_expiry_;
}

// ========== client 实现 ==========
client::client(const char* ip, const int port, const char* device) :
    m_ip_(ip), m_port_(port), m_device_(device), m_is_reg_(false) {}

auto client::set_rtp_port(const int rtp_port) -> void {
    m_rtp_port_ = rtp_port;
}

auto client::set_reg(const bool is_reg) -> void {
    m_is_reg_ = is_reg;
}

auto client::get_device() const -> const char* {
    return m_device_;
}

auto client::get_ip() const -> const char* {
    return m_ip_;
}

auto client::get_port() const -> int {
    return m_port_;
}

auto client::is_registered() const -> bool {
    return m_is_reg_;
}

// ========== sip_server 构造和析构 ==========
sip_server::sip_server(server_info* info) :
    m_quit_(false), m_running_(false), m_sip_ctx_(nullptr), m_info_(info),
    m_download_root_path_("./video_downloads/"), m_snapshot_root_path_("./snapshots/") {
    // 创建目录
    std::filesystem::create_directories(m_download_root_path_);
    std::filesystem::create_directories(m_snapshot_root_path_);

#ifdef WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOGE("WSAStartup Error");
        return;
    }
#endif
    LOGI("SIP服务器对象创建完成");
}

sip_server::~sip_server() {
    LOGI("SIP服务器析构开始");
    stop();

    // 清理资源
    clear_client_map();

    if (m_sip_ctx_ != nullptr) {
        eXosip_quit(m_sip_ctx_);
        m_sip_ctx_ = nullptr;
    }

#ifdef WIN32
    WSACleanup();
#endif
    LOGI("SIP服务器析构完成");
}

// ========== 服务器控制接口实现 ==========
auto sip_server::start() -> int {
    if (m_running_) {
        LOGI("SIP服务器已在运行中");
        return 0;
    }

    LOGI("启动SIP服务器");

    if (init_sip_server() != 0) {
        LOGE("SIP服务器初始化失败");
        return -1;
    }

    m_quit_ = false;
    m_running_ = true;

    // 创建服务器线程
    m_server_thread_ = std::make_unique<std::thread>([this] {
        this->loop();
    });

    LOGI("SIP服务器启动成功");
    return 0;
}

auto sip_server::stop() -> void {
    if (!m_running_) {
        return;
    }

    LOGI("停止SIP服务器");
    m_quit_ = true;
    m_running_ = false;

    // 等待服务器线程结束
    if (m_server_thread_ && m_server_thread_->joinable()) {
        m_server_thread_->join();
        m_server_thread_.reset();
    }

    // 清理各种会话
    {
        std::lock_guard lock(m_download_mutex_);
        for (auto& session : m_download_sessions_ | std::views::values) {
            if (session.download_thread && session.download_thread->joinable()) {
                session.download_thread->detach();
            }
        }
        m_download_sessions_.clear();
    }

    {
        std::lock_guard lock(m_snapshot_mutex_);
        m_snapshot_sessions_.clear();
    }

    {
        std::lock_guard lock(m_config_mutex_);
        m_device_configs_.clear();
    }

    {
        std::lock_guard lock(m_notify_mutex_);
        m_notify_messages_.clear();
    }

    // 清理回放会话
    for (const auto& session : m_playback_sessions_ | std::views::values) {
        if (session.call_id > 0) {
            eXosip_lock(m_sip_ctx_);
            eXosip_call_terminate(m_sip_ctx_, session.call_id, session.dialog_id);
            eXosip_unlock(m_sip_ctx_);
        }
    }
    m_playback_sessions_.clear();

    m_record_map_.clear();
    {
        std::lock_guard lock(m_query_mutex_);
        m_pending_queries_.clear();
    }

    LOGI("SIP服务器停止完成");
}

auto sip_server::is_running() const -> bool {
    return m_running_;
}

// ========== 设备管理接口实现 ==========
auto sip_server::get_registered_devices() const -> std::vector<std::string> {
    std::vector<std::string> devices;
    devices.reserve(m_client_map_.size());

    for (const auto& [device_id, client_ptr] : m_client_map_) {
        if (client_ptr && client_ptr->is_registered()) {
            devices.emplace_back(device_id);
        }
    }
    return devices;
}

auto sip_server::get_device_info(const char* device_id) const -> device_info {
    device_info info;
    if (!device_id) {
        return info;
    }

    // 首先在设备树中查找
    if (const auto it = m_device_tree_.find(device_id); it != m_device_tree_.end()) {
        return it->second;
    }

    // 如果在设备树中找不到，返回基本信息
    info.device_id = device_id;
    info.status = is_device_online(device_id) ? "ON" : "OFF";
    info.type = device_type::unknown;
    return info;
}

auto sip_server::get_all_camera_devices() const -> std::vector<device_info> {
    std::vector<device_info> cameras;

    for (const auto& device : m_device_tree_ | std::views::values) {
        if (device.type == device_type::camera && device.status == "ON") {
            cameras.push_back(device);
        }

        // 递归查找子设备中的摄像头
        std::function<void(const std::vector<device_info>&)> find_cameras =
            [&](const std::vector<device_info>& children) {
            for (const auto& child : children) {
                if (child.type == device_type::camera && child.status == "ON") {
                    cameras.push_back(child);
                }
                if (!child.children.empty()) {
                    find_cameras(child.children);
                }
            }
        };

        find_cameras(device.children);
    }

    return cameras;
}

auto sip_server::find_device_in_tree(const char* device_id) const -> device_info* {
    if (!device_id) {
        return nullptr;
    }

    // 先在设备树缓存中查找
    const auto it = m_device_tree_.find(device_id);
    if (it != m_device_tree_.end()) {
        return const_cast<device_info*>(&it->second);
    }

    // 在目录中查找
    for (const auto& catalog : m_device_catalogs_ | std::views::values) {
        for (auto& child : catalog) {
            if (child.device_id == device_id) {
                return const_cast<device_info*>(&child);
            }
        }
    }

    return nullptr;
}

auto sip_server::get_device_parent_info(const char* device_id) const -> std::pair<std::string, int> {
    if (!device_id) {
        return {"", 0};
    }

    // 首先在设备树中查找
    if (auto* device_info = find_device_in_tree(device_id); device_info && !device_info->parent_device_id.empty()) {
        // 找到了父设备ID，现在获取父设备的网络信息
        if (!device_info->parent_ip.empty() && device_info->parent_port > 0) {
            return {device_info->parent_ip, device_info->parent_port};
        }

        // 如果没有存储父设备的IP/端口，从客户端列表查找
        if (const auto parent_client = get_client_by_device(device_info->parent_device_id.c_str())) {
            return {parent_client->get_ip(), parent_client->get_port()};
        }
    }

    // 如果在设备树中找不到，检查目录
    for (const auto& [parent_id, catalog] : m_device_catalogs_) {
        for (const auto& child : catalog) {
            if (child.device_id == device_id) {
                // 找到了，获取父设备的网络信息
                if (const auto parent_client = get_client_by_device(parent_id.c_str())) {
                    return {parent_client->get_ip(), parent_client->get_port()};
                }
            }
        }
    }

    return {"", 0};
}

// 设备类型判断函数
static auto determine_device_type(const std::string& model, const std::string& device_id) -> device_type {
    // 根据型号判断设备类型
    if (model == "Camera" || model == "IP Camera" || model == "IPCamera" || model == "IPdome") {
        return device_type::camera;
    }

    if (model == "NVR" || model == "DVR") {
        return device_type::nvr;
    }

    if (model == "AudioOut" || model.find("Audio") != std::string::npos) {
        return device_type::audio_out;
    }

    // 根据设备ID规则判断（GB28181标准）
    if (device_id.length() >= 20) {
        std::string type_code = device_id.substr(10, 3);
        if (type_code >= "131" && type_code <= "134") {
            return device_type::camera;
        }
        if (type_code >= "111" && type_code <= "118") {
            return device_type::nvr;
        }
        if (type_code == "137") {
            return device_type::audio_out;
        }
    }

    return device_type::unknown;
}

auto sip_server::is_device_online(const char* device_id) const -> bool {
    if (!device_id) {
        return false;
    }

    const auto it = m_client_map_.find(device_id);
    return it != m_client_map_.end() && it->second && it->second->is_registered();
}

// ========== SIP协议初始化 ==========
auto sip_server::init_sip_server() -> int {
    eXosip_t* temp_sip_ctx = eXosip_malloc();
    if (temp_sip_ctx == nullptr) {
        LOGE("eXosip_malloc failed");
        return -1;
    }

    if (eXosip_init(temp_sip_ctx) != 0) {
        LOGE("eXosip_init failed");
        return -1;
    }

    if (eXosip_listen_addr(temp_sip_ctx, IPPROTO_UDP, m_info_->get_ip(),
                           m_info_->get_port(), AF_INET, 0) != 0) {
        LOGE("eXosip_listen_addr failed");
        eXosip_quit(temp_sip_ctx);
        return -1;
    }

    eXosip_set_user_agent(temp_sip_ctx, m_info_->get_ua());

    if (eXosip_add_authentication_info(temp_sip_ctx, m_info_->get_sip_id(),
                                       m_info_->get_sip_id(), m_info_->get_sip_pass(),
                                       nullptr, m_info_->get_sip_realm()) != 0) {
        LOGE("eXosip_add_authentication_info failed");
        eXosip_quit(temp_sip_ctx);
        return -1;
    }

    m_sip_ctx_ = temp_sip_ctx;
    return 0;
}

// ========== SIP事件循环 ==========
auto sip_server::loop() -> void {
    LOGI("SIP服务器事件循环开始");

    while (!m_quit_) {
        eXosip_event_t* evtp = eXosip_event_wait(m_sip_ctx_, 0, 20);

        if (evtp == nullptr) {
            eXosip_automatic_action(m_sip_ctx_);

            // 定期清理
            auto now = std::chrono::steady_clock::now();
            const auto cleanup_duration = std::chrono::duration_cast<std::chrono::seconds>(
                now - m_last_cleanup_).count();

            if (cleanup_duration >= cleanup_interval_seconds) {
                cleanup_expired_sessions();
                cleanup_expired_queries();
                cleanup_expired_downloads();
                cleanup_expired_snapshots();
                m_last_cleanup_ = now;
            }

            osip_usleep(100000);
            continue;
        }

        eXosip_automatic_action(m_sip_ctx_);
        sip_event_handle(evtp);
        eXosip_event_free(evtp);
    }

    LOGI("SIP服务器事件循环结束");
}

// ========== 工具方法实现 ==========
auto sip_server::parse_xml(const char* src, const char* start_tag, const char* end_tag,
                           char* dest, const long dest_size) -> int {
    if (!src || !start_tag || !end_tag || !dest || dest_size < 1) {
        return -1;
    }

    const char* start_pos = strstr(src, start_tag);
    if (!start_pos) {
        return -1;
    }

    const char* content_start = start_pos + strlen(start_tag);
    const char* end_pos = strstr(content_start, end_tag);
    if (!end_pos) {
        return -1;
    }

    const long content_len = end_pos - content_start;
    if (content_len + 1 > dest_size) {
        return -1;
    }

    strncpy(dest, content_start, content_len);
    dest[content_len] = '\0';
    return 0;
}

auto sip_server::send_sip_message(const char* device, const char* content) const -> int {
    if (!device || !content) {
        LOGE("send_sip_message: 输入参数无效");
        return -1;
    }

    // 首先检查是否为子设备，如果是则获取父设备信息
    auto [parent_ip, parent_port] = get_device_parent_info(device);

    const char* target_ip = nullptr;
    int target_port = 0;

    if (!parent_ip.empty() && parent_port > 0) {
        // 这是子设备，使用父设备的地址发送
        target_ip = parent_ip.c_str();
        target_port = parent_port;
        LOGI("子设备 %s 消息路由到父设备 %s:%d", device, target_ip, target_port);
    }
    else {
        // 这是根设备或未找到父设备信息，直接发送
        const client* client_ptr = get_client_by_device(device);
        if (!client_ptr) {
            LOGE("Device %s not found (not registered)", device);
            return -1;
        }
        target_ip = client_ptr->get_ip();
        target_port = client_ptr->get_port();
    }

    char to_uri[256];
    snprintf(to_uri, sizeof(to_uri), "sip:%s@%s:%d",
             device, target_ip, target_port);

    char from_uri[256];
    snprintf(from_uri, sizeof(from_uri), "sip:%s@%s:%d",
             m_info_->get_sip_id(), m_info_->get_ip(), m_info_->get_port());

    osip_message_t* msg = nullptr;
    eXosip_lock(m_sip_ctx_);
    int ret = eXosip_message_build_request(m_sip_ctx_, &msg, "MESSAGE", to_uri, from_uri, nullptr);
    if (ret != 0 || !msg) {
        LOGE("Failed to build MESSAGE request: %d", ret);
        eXosip_unlock(m_sip_ctx_);
        return -1;
    }

    osip_message_set_body(msg, content, strlen(content));
    osip_message_set_content_type(msg, "Application/MANSCDP+xml; charset=GB2312");

    ret = eXosip_message_send_request(m_sip_ctx_, msg);
    eXosip_unlock(m_sip_ctx_);

    if (ret < 0) {
        LOGE("Failed to send MESSAGE request to %s", to_uri);
        return -1;
    }

    LOGI("SIP MESSAGE sent to %s", to_uri);
    return 0;
}

auto sip_server::get_client_by_device(const char* device) const -> client* {
    if (!device) {
        return nullptr;
    }

    const auto it = m_client_map_.find(device);
    return (it != m_client_map_.end()) ? it->second : nullptr;
}

auto sip_server::clear_client_map() -> void {
    for (const auto& client_ptr : m_client_map_ | std::views::values) {
        delete client_ptr;
    }
    m_client_map_.clear();
    clients_set_.clear();
}

auto sip_server::dump_request(const eXosip_event_t* evtp) -> void {
    if (!evtp || !evtp->request) {
        return;
    }

    char* s = nullptr;
    size_t len = 0;
    osip_message_to_str(evtp->request, &s, &len);
    if (s) {
        // 这里可以根据需要打印请求内容
        osip_free(s);
    }
}

auto sip_server::dump_response(const eXosip_event_t* evtp) -> void {
    if (!evtp || !evtp->response) {
        return;
    }

    char* s = nullptr;
    size_t len = 0;
    osip_message_to_str(evtp->response, &s, &len);
    if (s) {
        // 这里可以根据需要打印响应内容
        osip_free(s);
    }
}

// ========== SIP事件处理实现 ==========
auto sip_server::sip_event_handle(const eXosip_event_t* evtp) -> void {
    switch (evtp->type) {
    case EXOSIP_CALL_MESSAGE_NEW:
        LOGI("EXOSIP_CALL_MESSAGE_NEW type=%d", evtp->type);
        dump_request(evtp);
        dump_response(evtp);
        break;

    case EXOSIP_CALL_CLOSED:
        LOGI("EXOSIP_CALL_CLOSED type=%d", evtp->type);
        dump_request(evtp);
        dump_response(evtp);
        break;

    case EXOSIP_CALL_RELEASED:
        LOGI("EXOSIP_CALL_RELEASED type=%d", evtp->type);
        dump_request(evtp);
        dump_response(evtp);
        break;

    case EXOSIP_MESSAGE_NEW:
        if (MSG_IS_REGISTER(evtp->request)) {
            LOGI("EXOSIP_MESSAGE_NEW type=%d", evtp->type);
            response_register(evtp);
        }
        else if (MSG_IS_MESSAGE(evtp->request)) {
            response_message(evtp);
        }
        break;

    case EXOSIP_MESSAGE_ANSWERED:
        LOGI("EXOSIP_MESSAGE_ANSWERED type=%d", evtp->type);
        dump_request(evtp);
        break;

    case EXOSIP_MESSAGE_REQUESTFAILURE:
        LOGI("EXOSIP_MESSAGE_REQUESTFAILURE type=%d", evtp->type);
        dump_request(evtp);
        dump_response(evtp);
        break;

    case EXOSIP_CALL_INVITE:
        LOGI("EXOSIP_CALL_INVITE type=%d", evtp->type);
        break;

    case EXOSIP_CALL_PROCEEDING:
        LOGI("EXOSIP_CALL_PROCEEDING type=%d", evtp->type);
        dump_request(evtp);
        dump_response(evtp);
        break;

    case EXOSIP_CALL_ANSWERED:
        LOGI("EXOSIP_CALL_ANSWERED type=%d", evtp->type);
        dump_request(evtp);
        dump_response(evtp);
        response_invite_ack(evtp);

        // 处理回放会话建立
        if (evtp->response && evtp->response->status_code == 200) {
            osip_body_t* body = nullptr;
            osip_message_get_body(evtp->response, 0, &body);
            if (body && strstr(body->body, "s=Playback")) {
                LOGI("回放会话建立成功");
                // 这里可以添加回放开始的处理逻辑
            }
        }
        break;

    case EXOSIP_CALL_SERVERFAILURE:
        LOGI("EXOSIP_CALL_SERVERFAILURE type=%d", evtp->type);
        break;

    case EXOSIP_IN_SUBSCRIPTION_NEW:
        LOGI("EXOSIP_IN_SUBSCRIPTION_NEW type=%d", evtp->type);
        break;

    default:
        LOGI("收到SIP事件类型: %d", evtp->type);
        if (evtp->type == 9) {
            // 特别处理回放错误
            LOGI("========== 回放错误事件分析 ==========");
            if (evtp->response) {
                LOGI("响应状态码: %d", evtp->response->status_code);
                if (evtp->response->reason_phrase) {
                    LOGI("错误原因: %s", evtp->response->reason_phrase);
                }

                // 清理失败的回放会话
                if (evtp->response->status_code >= 400) {
                    for (auto it = m_playback_sessions_.begin(); it != m_playback_sessions_.end(); ++it) {
                        if (it->second.call_id == evtp->cid) {
                            LOGI("清理失败的回放会话: %s", it->first.c_str());
                            m_playback_sessions_.erase(it);
                            break;
                        }
                    }
                }
            }
            LOGI("=====================================");
        }
        break;
    }
}

auto sip_server::response_message_answer(const eXosip_event_t* evtp, const int code) const -> void {
    osip_message_t* p_register = nullptr;

    int return_code = eXosip_message_build_answer(m_sip_ctx_, evtp->tid, code, &p_register);
    if (return_code == 0 && p_register) {
        eXosip_lock(m_sip_ctx_);
        eXosip_message_send_answer(m_sip_ctx_, evtp->tid, code, p_register);
        eXosip_unlock(m_sip_ctx_);
    }
    else {
        LOGE("response_message_answer failed: code=%d, return_code=%d", code, return_code);
    }
}

#define SIPSTRDUPP(field) if (auth->field != nullptr) { (field) = osip_strdup_without_quote(auth->field); }

auto sip_server::response_register(const eXosip_event_t* evtp) -> void {
    osip_authorization_t* auth = nullptr;
    osip_message_get_authorization(evtp->request, 0, &auth);

    if (auth && auth->username) {
        char* method = nullptr;
        char* algorithm = nullptr;
        char* username = nullptr;
        char* realm = nullptr;
        char* nonce = nullptr;
        char* nonce_count = nullptr;
        char* uri = nullptr;

        osip_contact_t* contact = nullptr;
        osip_message_get_contact(evtp->request, 0, &contact);

        method = evtp->request->sip_method;
        char calc_response[HASHHEXLEN] = {};
        HASHHEX ha1 = "";
        HASHHEX ha2 = "";
        HASHHEX response = "";

        SIPSTRDUPP(algorithm);
        SIPSTRDUPP(username);
        SIPSTRDUPP(realm);
        SIPSTRDUPP(nonce);
        SIPSTRDUPP(nonce_count);
        SIPSTRDUPP(uri);

        DigestCalcHA1(algorithm, username, realm, const_cast<char*>(m_info_->get_sip_pass()), nonce, nonce_count, ha1);
        DigestCalcResponse(ha1, nonce, nonce_count, auth->cnonce, auth->message_qop, 0, method, uri, ha2, response);

        HASHHEX temp_ha1 = "";
        HASHHEX temp_response = "";
        DigestCalcHA1("REGISTER", username, const_cast<char*>(m_info_->get_sip_realm()),
                      const_cast<char*>(m_info_->get_sip_pass()),
                      const_cast<char*>(m_info_->get_nonce()), nullptr, temp_ha1);
        DigestCalcResponse(temp_ha1, const_cast<char*>(m_info_->get_nonce()), nullptr, nullptr, nullptr, 0, method, uri,
                           nullptr, temp_response);

        memcpy(calc_response, temp_response, HASHHEXLEN);
        char* end_ptr = nullptr;

        auto* client_var = new client(strdup(contact->url->host),
                                      static_cast<int>(strtol(contact->url->port, &end_ptr, 10)),
                                      strdup(username));

        if (memcmp(calc_response, response, HASHHEXLEN) == 0) {
            response_message_answer(evtp, 200);
            client_var->set_reg(true);

            LOGI("设备注册成功: %s@%s:%d", username, client_var->get_ip(), client_var->get_port());

            m_client_map_[client_var->get_device()] = client_var;
            clients_set_.insert(client_var);

            // 注册成功后不再自动请求目录，由用户主动调用
        }
        else {
            response_message_answer(evtp, 401);
            LOGE("设备认证失败: %s@%s:%d", username, client_var->get_ip(), client_var->get_port());
            delete client_var;
        }

        // 清理分配的内存
        osip_free(algorithm);
        osip_free(username);
        osip_free(realm);
        osip_free(nonce);
        osip_free(nonce_count);
        osip_free(uri);
    }
    else {
        response_register_401_unauthorized(evtp);
    }
}

auto sip_server::response_register_401_unauthorized(const eXosip_event_t* evtp) const -> void {
    char* dest = nullptr;
    osip_www_authenticate_t* header = nullptr;

    osip_www_authenticate_init(&header);
    osip_www_authenticate_set_auth_type(header, osip_strdup("Digest"));
    osip_www_authenticate_set_realm(header, osip_enquote(m_info_->get_sip_realm()));
    osip_www_authenticate_set_nonce(header, osip_enquote(m_info_->get_nonce()));
    osip_www_authenticate_to_str(header, &dest);

    osip_message_t* reg = nullptr;
    int ret = eXosip_message_build_answer(m_sip_ctx_, evtp->tid, 401, &reg);
    if (ret == 0 && reg) {
        osip_message_set_www_authenticate(reg, dest);
        osip_message_set_content_type(reg, "Application/MANSCDP+xml");
        eXosip_lock(m_sip_ctx_);
        eXosip_message_send_answer(m_sip_ctx_, evtp->tid, 401, reg);
        eXosip_unlock(m_sip_ctx_);
        LOGI("发送401认证请求成功");
    }
    else {
        LOGE("发送401认证请求失败");
    }

    osip_www_authenticate_free(header);
    osip_free(dest);
}

auto sip_server::response_message(const eXosip_event_t* evtp) -> void {
    char cmd_type[64] = {};
    char device_id[64] = {};

    osip_body_t* body = nullptr;
    osip_message_get_body(evtp->request, 0, &body);

    if (!body) {
        LOGI("SIP MESSAGE无body内容");
        response_message_answer(evtp, 400);
        return;
    }

    if (parse_xml(body->body, "<CmdType>", "</CmdType>", cmd_type, sizeof(cmd_type)) != 0) {
        LOGI("解析CmdType失败");
        response_message_answer(evtp, 400);
        return;
    }

    if (parse_xml(body->body, "<DeviceID>", "</DeviceID>", device_id, sizeof(device_id)) != 0) {
        LOGI("解析DeviceID失败");
        response_message_answer(evtp, 400);
        return;
    }

    //LOGI("收到消息: CmdType=%s, DeviceID=%s", cmd_type, device_id);

    // 根据消息类型分发处理
    if (strcmp(cmd_type, "Catalog") == 0) {
        parse_catalog_response(body->body);
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "Keepalive") == 0) {
        // 检查设备是否已注册
        if (const auto client = get_client_by_device(device_id); !client) {
            // 可能是子设备的心跳，忽略
            LOGD("收到未注册设备的心跳: %s，忽略", device_id);
        }
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "RecordInfo") == 0) {
        parse_record_info_response(body->body);
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "MediaStatus") == 0) {
        handle_playback_info(evtp);
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "DownloadInfo") == 0) {
        parse_download_info_response(body->body);
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "DownloadStatus") == 0) {
        handle_download_response(evtp);
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "DeviceControl") == 0) {
        parse_snapshot_response(body->body);
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "ConfigDownload") == 0) {
        parse_device_config_response(body->body);
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "Notify") == 0) {
        handle_notify_message(evtp);
        response_message_answer(evtp, 200);
    }
    else if (strcmp(cmd_type, "SnapShotNotify") == 0) {
        handle_snapshot_notify(evtp);
        response_message_answer(evtp, 200);
    }
    else {
        LOGI("收到未知消息类型: %s", cmd_type);
        response_message_answer(evtp, 200);
    }
}

auto sip_server::response_invite_ack(const eXosip_event_t* evtp) const -> void {
    osip_message_t* msg = nullptr;
    int ret = eXosip_call_build_ack(m_sip_ctx_, evtp->did, &msg);
    if (ret == 0 && msg) {
        eXosip_call_send_ack(m_sip_ctx_, evtp->did, msg);
    }
    else {
        LOGE("eXosip_call_send_ack error=%d", ret);
    }
}

auto sip_server::request_bye(const eXosip_event_t* evtp) const -> int {
    eXosip_lock(m_sip_ctx_);
    int ret = eXosip_call_terminate(m_sip_ctx_, evtp->cid, evtp->did);
    eXosip_unlock(m_sip_ctx_);
    return ret;
}

auto sip_server::request_invite(const char* device, const char* user_ip, const long user_port) const -> int {
    if (!device || !user_ip) {
        LOGE("request_invite: 输入参数无效");
        return -1;
    }

    char from[1024];
    char to[1024];
    char sdp[2048];

    snprintf(from, sizeof(from), "sip:%s@%s:%d",
             m_info_->get_sip_id(), m_info_->get_ip(), m_info_->get_port());
    snprintf(to, sizeof(to), "sip:%s@%s:%ld", device, user_ip, user_port);

    snprintf(sdp, sizeof(sdp),
             "v=0\r\n"
             "o=%s 0 0 IN IP4 %s\r\n"
             "s=Play\r\n"
             "c=IN IP4 %s\r\n"
             "t=0 0\r\n"
             "m=video %d TCP/RTP/AVP 96 98 97\r\n"
             "a=recvonly\r\n"
             "a=rtpmap:96 PS/90000\r\n"
             "a=rtpmap:98 H264/90000\r\n"
             "a=rtpmap:97 MPEG4/90000\r\n"
             "a=setup:passive\r\n"
             "a=connection:new\r\n"
             "y=0100000001\r\n"
             "f=v/5/6/25/1/5000a/0/8/1\r\n",
             m_info_->get_sip_id(), m_info_->get_ip(), m_info_->get_ip(), m_info_->get_rtp_port());

    osip_message_t* msg = nullptr;
    int ret = eXosip_call_build_initial_invite(m_sip_ctx_, &msg, to, from, nullptr, nullptr);
    if (ret != 0) {
        LOGE("eXosip_call_build_initial_invite error: %d", ret);
        return -1;
    }

    osip_message_set_body(msg, sdp, strlen(sdp));
    osip_message_set_content_type(msg, "application/sdp");

    char session_exp[1024];
    snprintf(session_exp, sizeof(session_exp) - 1, "%i;refresher=uac", m_info_->get_timeout());
    osip_message_set_header(msg, "Session-Expires", session_exp);
    osip_message_set_supported(msg, "timer");

    int call_id = eXosip_call_send_initial_invite(m_sip_ctx_, msg);
    if (call_id > 0) {
        LOGI("INVITE请求发送成功: call_id=%d", call_id);
        return call_id;
    }
    LOGE("INVITE请求发送失败: call_id=%d", call_id);
    return -1;
}

// ========== 设备目录接口实现 ==========
auto sip_server::request_catalog(const char* device_id) const -> int {
    if (!device_id) {
        LOGE("request_catalog: 设备ID为空");
        return -1;
    }

    if (!is_device_online(device_id)) {
        LOGE("设备%s未在线", device_id);
        return -1;
    }

    char xml_body[512];
    long sn = random() % 10000 + 1;

    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\"?>\r\n"
             "<Query>\r\n"
             "<CmdType>Catalog</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "</Query>",
             sn, device_id);

    LOGI("请求设备目录: %s", device_id);
    return send_sip_message(device_id, xml_body);
}

auto sip_server::get_device_catalog(const char* device_id) const -> std::vector<device_info> {
    if (!device_id) {
        return {};
    }

    auto it = m_device_catalogs_.find(device_id);
    return (it != m_device_catalogs_.end()) ? it->second : std::vector<device_info>{};
}

// 编码转换函数
static auto gb2312_to_utf8(const std::string& gb2312_str) -> std::string {
    iconv_t cd = iconv_open("UTF-8", "GB2312");
    if (cd == reinterpret_cast<iconv_t>(-1)) {
        LOGE("iconv_open失败");
        return "";
    }

    size_t in_len = gb2312_str.size();
    size_t out_len = in_len * 2;
    char* in_buf = const_cast<char*>(gb2312_str.c_str());
    char* out_buf = new char[out_len];
    char* out_ptr = out_buf;

    if (iconv(cd, &in_buf, &in_len, &out_ptr, &out_len) == static_cast<size_t>(-1)) {
        LOGE("iconv转换失败");
        iconv_close(cd);
        delete[] out_buf;
        return "";
    }

    std::string utf8_str(out_buf, out_ptr - out_buf);
    iconv_close(cd);
    delete[] out_buf;
    return utf8_str;
}

auto sip_server::parse_catalog_response(const char* xml) -> void {
    if (!xml || strlen(xml) == 0) {
        LOGE("parse_catalog_response: 输入XML为空");
        return;
    }

    std::string utf8_xml = gb2312_to_utf8(xml);
    if (utf8_xml.empty()) {
        LOGE("XML编码转换失败（GB2312→UTF-8）");
        return;
    }

    XMLDocument doc;
    if (XMLError err = doc.Parse(utf8_xml.c_str()); err != XML_SUCCESS) {
        LOGE("解析Catalog XML失败：%s", doc.ErrorName());
        return;
    }

    XMLElement* root = doc.RootElement();
    if (!root || strcmp(root->Name(), "Response") != 0) {
        LOGE("无效的Catalog响应：根元素不是Response");
        return;
    }

    XMLElement* device_id_elem = root->FirstChildElement("DeviceID");
    if (!device_id_elem || !device_id_elem->GetText()) {
        LOGE("Catalog响应缺少DeviceID");
        return;
    }
    std::string parent_device_id = device_id_elem->GetText();

    // 获取总数和当前响应中的设备数
    int sum_num = 0;
    if (XMLElement* sum_num_elem = root->FirstChildElement("SumNum")) {
        if (sum_num_elem->GetText()) {
            try {
                sum_num = std::stoi(sum_num_elem->GetText());
            }
            catch (const std::exception& e) {
                LOGE("SumNum转换失败: %s", e.what());
            }
        }
    }

    // 获取父设备的IP和端口信息
    std::string parent_ip;
    int parent_port = 0;
    if (auto client = get_client_by_device(parent_device_id.c_str())) {
        parent_ip = client->get_ip();
        parent_port = client->get_port();
    }

    // 使用静态变量跟踪每个设备的接收进度
    static std::map<std::string, int> device_catalog_counts;
    static std::map<std::string, std::set<std::string>> device_received_items;

    // 如果是新查询，清空之前的记录
    if (!device_catalog_counts.contains(parent_device_id)) {
        m_device_catalogs_[parent_device_id].clear();
        device_catalog_counts[parent_device_id] = 0;
        device_received_items[parent_device_id].clear();
    }

    XMLElement* device_list_elem = root->FirstChildElement("DeviceList");
    if (!device_list_elem) {
        LOGI("Catalog响应中无DeviceList元素，设备总数: %d", sum_num);
        return;
    }

    int current_batch_count = 0;
    for (XMLElement* item_elem = device_list_elem->FirstChildElement("Item");
         item_elem != nullptr;
         item_elem = item_elem->NextSiblingElement("Item")) {
        XMLElement* device_id_sub = item_elem->FirstChildElement("DeviceID");
        if (!device_id_sub || !device_id_sub->GetText()) {
            continue;
        }

        std::string child_device_id = device_id_sub->GetText();

        // 检查是否已经接收过这个设备
        if (device_received_items[parent_device_id].contains(child_device_id)) {
            continue; // 跳过已接收的设备
        }

        device_info info;
        info.device_id = child_device_id;
        info.parent_device_id = parent_device_id;
        info.parent_ip = parent_ip;
        info.parent_port = parent_port;

        // 解析其他字段
        if (XMLElement* name_elem = item_elem->FirstChildElement("Name")) {
            if (name_elem->GetText()) {
                info.name = name_elem->GetText();
            }
        }
        if (XMLElement* model_elem = item_elem->FirstChildElement("Model")) {
            if (model_elem->GetText()) {
                info.model = model_elem->GetText();
            }
        }
        if (XMLElement* status_elem = item_elem->FirstChildElement("Status")) {
            if (status_elem->GetText()) {
                info.status = status_elem->GetText();
            }
        }
        if (XMLElement* manufacturer_elem = item_elem->FirstChildElement("Manufacturer")) {
            if (manufacturer_elem->GetText()) {
                info.manufacturer = manufacturer_elem->GetText();
            }
        }
        if (XMLElement* address_elem = item_elem->FirstChildElement("Address")) {
            if (address_elem->GetText()) {
                info.address = address_elem->GetText();
            }
        }

        // 确定设备类型
        info.type = determine_device_type(info.model, info.device_id);

        // 只处理摄像头和录像机设备
        if (info.type == device_type::camera || info.type == device_type::nvr) {
            m_device_catalogs_[parent_device_id].push_back(info);
            m_device_tree_[info.device_id] = info;
            device_received_items[parent_device_id].insert(child_device_id);
            current_batch_count++;

            if (info.type == device_type::camera) {
                m_camera_device_ids_.insert(info.device_id);
                LOGI("添加摄像头设备：ID=%s, 名称=%s, 状态=%s",
                     info.device_id.c_str(), info.name.c_str(), info.status.c_str());
            }
            else if (info.type == device_type::nvr) {
                LOGI("添加录像机设备：ID=%s, 名称=%s, 状态=%s",
                     info.device_id.c_str(), info.name.c_str(), info.status.c_str());
            }
        }
    }

    device_catalog_counts[parent_device_id] += current_batch_count;

    LOGI("设备%s目录片段解析完成，本批次%d个设备，累计%d/%d",
         parent_device_id.c_str(), current_batch_count,
         device_catalog_counts[parent_device_id], sum_num);

    // 检查是否已接收完所有设备
    if (sum_num > 0 && device_catalog_counts[parent_device_id] >= sum_num) {
        LOGI("设备%s的所有目录已接收完成，共%zu个有效设备",
             parent_device_id.c_str(), m_device_catalogs_[parent_device_id].size());
        device_catalog_counts.erase(parent_device_id);
        device_received_items.erase(parent_device_id);
    }
}

// ========== PTZ控制接口实现 ==========
auto sip_server::send_ptz_control(const char* device_id, ptz_command cmd, int speed) const -> int {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    // 构造PTZ命令
    constexpr uint8_t device_addr_high = 0x00U;
    constexpr uint8_t device_addr_low = 0x01U;
    constexpr uint8_t byte1 = 0xA5U;
    constexpr uint8_t version = 0x0U;
    constexpr uint8_t byte1_high = byte1 >> 0x4U & 0xFU;
    constexpr uint8_t byte1_low = byte1 & 0xFU;
    constexpr uint8_t checksum_byte2 = (byte1_high + byte1_low + version) % 0x10U;
    constexpr uint8_t byte2 = version << 0x4U | checksum_byte2;
    constexpr uint8_t byte3 = device_addr_low;

    uint8_t byte4 = 0x00U;
    switch (cmd) {
    case ptz_command::ptz_up: byte4 = 0x08U;
        break;
    case ptz_command::ptz_down: byte4 = 0x04U;
        break;
    case ptz_command::ptz_left: byte4 = 0x02U;
        break;
    case ptz_command::ptz_right: byte4 = 0x01U;
        break;
    case ptz_command::ptz_zoom_in: byte4 = 0x10U;
        break;
    case ptz_command::ptz_zoom_out: byte4 = 0x20U;
        break;
    case ptz_command::ptz_stop: byte4 = 0x00U;
        break;
    }

    uint8_t byte5 = 0x00U;
    uint8_t byte6 = 0x00U;
    uint8_t byte7 = (0x00U << 0x4U | device_addr_high) & 0xFU;

    if (cmd == ptz_command::ptz_up || cmd == ptz_command::ptz_down) {
        byte6 = static_cast<uint8_t>(speed);
    }
    else if (cmd == ptz_command::ptz_left || cmd == ptz_command::ptz_right) {
        byte5 = static_cast<uint8_t>(speed);
    }
    else if (cmd == ptz_command::ptz_zoom_in || cmd == ptz_command::ptz_zoom_out) {
        auto zoom_speed = static_cast<uint8_t>(speed);
        if (zoom_speed > 0xFU) {
            zoom_speed = 0xFU;
        }
        byte7 = (zoom_speed << 0x4U | device_addr_high) & 0xFFU;
    }

    const uint8_t checksum_byte8 = (byte1 + byte2 + byte3 + byte4 + byte5 + byte6 + byte7) & 0xFFU;

    char ptz_cmd[17];
    snprintf(ptz_cmd, sizeof(ptz_cmd), "%02X%02X%02X%02X%02X%02X%02X%02X",
             byte1, byte2, byte3, byte4, byte5, byte6, byte7, checksum_byte8);

    char xml_body[512];
    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\"?>\r\n"
             "<Control>\r\n"
             "<CmdType>DeviceControl</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "<PTZCmd>%s</PTZCmd>\r\n"
             "</Control>",
             random() % 10000 + 1, device_id, ptz_cmd);

    const char* cmd_names[] = {"UP", "DOWN", "LEFT", "RIGHT", "ZOOM_IN", "ZOOM_OUT", "STOP"};
    LOGI("发送PTZ控制: Device=%s, Command=%s, Speed=%d",
         device_id, cmd_names[static_cast<int>(cmd)], speed);

    return send_sip_message(device_id, xml_body);
}

auto sip_server::build_preset_cmd(preset_operation op, int preset_id) -> std::string {
    if (preset_id < 1 || preset_id > 255) {
        LOGE("预置位ID %d 超出范围 (1-255)", preset_id);
        return "";
    }

    uint8_t cmd_bytes[8] = {
        0xA5U, // 起始符
        0x0FU, // 固定值
        0x01U, // 命令类型
        0x00U, // 操作码
        0x00U, // 固定值
        0x00U, // 预置位编号
        0x00U, // 预留
        0x00U // 校验码
    };

    switch (op) {
    case preset_operation::set: cmd_bytes[3] = 0x81U;
        break;
    case preset_operation::call: cmd_bytes[3] = 0x82U;
        break;
    case preset_operation::remove: cmd_bytes[3] = 0x83U;
        break;
    }

    cmd_bytes[5] = static_cast<uint8_t>(preset_id);

    uint8_t checksum = 0;
    for (int i = 0; i < 7; ++i) {
        checksum += cmd_bytes[i];
    }
    cmd_bytes[7] = checksum;

    char cmd_str[17];
    snprintf(cmd_str, sizeof(cmd_str), "%02X%02X%02X%02X%02X%02X%02X%02X",
             cmd_bytes[0], cmd_bytes[1], cmd_bytes[2], cmd_bytes[3],
             cmd_bytes[4], cmd_bytes[5], cmd_bytes[6], cmd_bytes[7]);

    return std::string{cmd_str};
}

auto sip_server::send_preset_control(const char* device_id, preset_operation op, const int preset_id) const -> int {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    const std::string ptz_cmd = build_preset_cmd(op, preset_id);
    if (ptz_cmd.empty()) {
        return -1;
    }

    char xml_body[512];
    const long sn = random() % 10000 + 1;
    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
             "<Control>"
             "<CmdType>DeviceControl</CmdType>"
             "<SN>%ld</SN>"
             "<DeviceID>%s</DeviceID>"
             "<PTZCmd>%s</PTZCmd>"
             "</Control>",
             sn, device_id, ptz_cmd.c_str());

    const char* op_names[] = {"SET", "CALL", "REMOVE"};
    LOGI("发送预置位控制: Device=%s, Operation=%s, PresetID=%d",
         device_id, op_names[static_cast<int>(op)], preset_id);

    return send_sip_message(device_id, xml_body);
}

auto sip_server::send_ptz_position_query(const char* device_id) const -> int {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    char xml_body[1024];
    const long sn = random() % 10000 + 1;

    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"
             "<Query>\r\n"
             "<CmdType>PTZPosition</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "</Query>\r\n",
             sn, device_id);

    LOGI("查询PTZ位置: %s", device_id);
    return send_sip_message(device_id, xml_body);
}

// ========== 录像管理接口实现 ==========
auto sip_server::request_record_query(const char* device_id, const char* start_time,
                                      const char* end_time, const char* type) const -> int {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    // 初始化查询状态
    {
        std::lock_guard lock(m_query_mutex_);
        auto& query_state = m_pending_queries_[device_id];
        query_state.device_id = device_id;
        query_state.start_time = start_time;
        query_state.end_time = end_time;
        query_state.query_type = type ? type : "all";
        query_state.expected_total = 0;
        query_state.received_count = 0;
        query_state.query_complete = false;
        query_state.playback_initiated = false;
        query_state.last_query_time = std::chrono::steady_clock::now();
    }

    char xml_body[1024];
    long sn = random() % 10000 + 1;

    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\"?>\r\n"
             "<Query>\r\n"
             "<CmdType>RecordInfo</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "<StartTime>%s</StartTime>\r\n"
             "<EndTime>%s</EndTime>\r\n"
             "<Secrecy>0</Secrecy>\r\n"
             "<Type>%s</Type>\r\n"
             "</Query>",
             sn, device_id, start_time, end_time, type ? type : "all");

    LOGI("请求录像查询: Device=%s, Time=%s~%s, Type=%s",
         device_id, start_time, end_time, type ? type : "all");

    return send_sip_message(device_id, xml_body);
}

auto sip_server::get_record_list(const char* device_id) const -> std::vector<record_info> {
    if (!device_id) {
        return {};
    }

    const auto it = m_record_map_.find(device_id);
    return (it != m_record_map_.end()) ? it->second : std::vector<record_info>{};
}

// ========== 录像信息解析实现 ==========
auto sip_server::parse_record_info_response(const char* xml) -> void {
    if (!xml || strlen(xml) == 0) {
        LOGE("parse_record_info_response: 输入XML为空");
        return;
    }

    std::string utf8_xml = gb2312_to_utf8(xml);
    if (utf8_xml.empty()) {
        LOGE("录像信息XML编码转换失败（GB2312->UTF-8）");
        return;
    }

    XMLDocument doc;
    if (XMLError err = doc.Parse(utf8_xml.c_str()); err != XML_SUCCESS) {
        LOGE("解析RecordInfo XML失败：%s", doc.ErrorName());
        return;
    }

    XMLElement* root = doc.RootElement();
    if (!root || strcmp(root->Name(), "Response") != 0) {
        LOGE("无效的RecordInfo响应：根元素不正确");
        return;
    }

    XMLElement* cmd_type_elem = root->FirstChildElement("CmdType");
    if (!cmd_type_elem || !cmd_type_elem->GetText() || strcmp(cmd_type_elem->GetText(), "RecordInfo") != 0) {
        LOGE("无效的RecordInfo响应：CmdType不正确");
        return;
    }

    XMLElement* device_id_elem = root->FirstChildElement("DeviceID");
    if (!device_id_elem || !device_id_elem->GetText()) {
        LOGE("RecordInfo响应缺少有效的DeviceID");
        return;
    }
    std::string device_id = device_id_elem->GetText();

    int sum_num = 0;
    if (XMLElement* sum_num_elem = root->FirstChildElement("SumNum");
        sum_num_elem && sum_num_elem->GetText()) {
        try {
            sum_num = std::stoi(sum_num_elem->GetText());
        }
        catch ([[maybe_unused]] const std::exception& e) {
            LOGE("SumNum转换失败: %s", sum_num_elem->GetText());
            return;
        }
    }

    XMLElement* record_list_elem = root->FirstChildElement("RecordList");
    if (!record_list_elem) {
        LOGI("设备%s无录像记录（总数: %d）", device_id.c_str(), sum_num);

        std::lock_guard lock(m_query_mutex_);
        if (auto it = m_pending_queries_.find(device_id); it != m_pending_queries_.end()) {
            it->second.expected_total = sum_num;
            it->second.received_count = 0;
            it->second.query_complete = true;
        }
        return;
    }

    std::vector<record_info> records;
    for (XMLElement* item_elem = record_list_elem->FirstChildElement("Item");
         item_elem != nullptr;
         item_elem = item_elem->NextSiblingElement("Item")) {
        record_info record;
        record.device_id = device_id;

        auto parse_field = [&](const char* field_name, std::string& target) -> bool {
            if (XMLElement* elem = item_elem->FirstChildElement(field_name);
                elem && elem->GetText()) {
                target = elem->GetText();
                return true;
            }
            return false;
        };

        if (!parse_field("StartTime", record.start_time) ||
            !parse_field("EndTime", record.end_time)) {
            continue; // 跳过缺少时间信息的记录
        }

        parse_field("Name", record.name);
        parse_field("FilePath", record.file_path);
        parse_field("Address", record.address);
        parse_field("RecorderID", record.recorder_id);
        parse_field("Type", record.type);

        if (XMLElement* size_elem = item_elem->FirstChildElement("FileSize");
            size_elem && size_elem->GetText()) {
            try {
                record.file_size = std::stoull(size_elem->GetText());
            }
            catch (const std::exception&) {
                record.file_size = 0;
            }
        }

        records.push_back(record);
    }

    // 保存录像记录
    auto& device_records = m_record_map_[device_id];
    device_records.insert(device_records.end(), records.begin(), records.end());

    // 更新查询状态
    {
        std::lock_guard lock(m_query_mutex_);
        if (auto it = m_pending_queries_.find(device_id); it != m_pending_queries_.end()) {
            it->second.expected_total = sum_num;
            it->second.received_count += static_cast<int>(records.size());
            it->second.last_query_time = std::chrono::steady_clock::now();

            if (it->second.received_count >= it->second.expected_total) {
                it->second.query_complete = true;
                LOGI("设备%s录像查询完成，共%d条记录",
                     device_id.c_str(), it->second.received_count);
            }
            else {
                LOGI("设备%s录像查询进度：%d/%d",
                     device_id.c_str(), it->second.received_count, it->second.expected_total);
            }
        }
    }

    LOGI("设备%s本批次解析录像记录：%zu条", device_id.c_str(), records.size());
}

// ========== 回放控制接口实现 ==========
auto sip_server::start_playback(const char* device_id, const char* start_time, const char* end_time) -> std::string {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return "";
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return "";
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return "";
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return "";
        }
    }

    // 检查是否有对应的录像记录
    auto record_it = m_record_map_.find(device_id);
    if (record_it == m_record_map_.end() || record_it->second.empty()) {
        LOGE("设备%s没有录像记录，请先查询录像", device_id);
        return "";
    }

    // 查找匹配的录像记录
    const record_info* matching_record = nullptr;
    for (const auto& record : record_it->second) {
        if (record.start_time == start_time && record.end_time == end_time) {
            matching_record = &record;
            break;
        }
    }

    if (!matching_record && !record_it->second.empty()) {
        // 如果没有精确匹配，使用第一条记录
        matching_record = &record_it->second[0];
        LOGI("未找到精确匹配的录像，使用第一条记录: %s~%s",
             matching_record->start_time.c_str(), matching_record->end_time.c_str());
        start_time = matching_record->start_time.c_str();
        end_time = matching_record->end_time.c_str();
    }

    if (!matching_record) {
        LOGE("未找到可回放的录像记录");
        return "";
    }

    // 生成回放会话
    std::string ssrc = generate_ssrc();
    int call_id = request_playback_invite(device_id, start_time, end_time);

    if (call_id <= 0) {
        LOGE("发起回放INVITE失败");
        return "";
    }

    // 保存会话信息
    playback_session session;
    session.session_id = ssrc;
    session.device_id = device_id;
    session.call_id = call_id;
    session.start_time = start_time;
    session.end_time = end_time;
    session.ssrc = ssrc;
    session.rtp_port = m_next_playback_port_++;
    session.is_playing = false;
    session.last_activity = std::chrono::steady_clock::now();
    session.dialog_id = 0;

    m_playback_sessions_[ssrc] = session;

    LOGI("回放会话创建成功: SessionID=%s, CallID=%d", ssrc.c_str(), call_id);
    return ssrc;
}

auto sip_server::control_playback(const char* session_id, playback_control control, const char* param) -> int {
    if (!session_id) {
        LOGE("control_playback: 会话ID为空");
        return -1;
    }

    const auto it = m_playback_sessions_.find(session_id);
    if (it == m_playback_sessions_.end()) {
        LOGE("回放会话不存在: %s", session_id);
        return -1;
    }

    const playback_session& session = it->second;
    const char* range = nullptr;
    const char* scale = nullptr;

    if (control == playback_control::seek) {
        range = param;
    }
    else if (control == playback_control::speed) {
        scale = param;
    }

    return send_playback_control(session.device_id.c_str(), session_id, control, range, scale);
}

auto sip_server::stop_playback(const char* session_id) -> int {
    if (!session_id) {
        LOGE("stop_playback: 会话ID为空");
        return -1;
    }

    const auto it = m_playback_sessions_.find(session_id);
    if (it == m_playback_sessions_.end()) {
        LOGE("回放会话不存在: %s", session_id);
        return -1;
    }

    const playback_session& session = it->second;

    // 发送停止命令
    const int ret = send_playback_control(session.device_id.c_str(), session_id, playback_control::stop, nullptr,
                                          nullptr);

    // 终止SIP会话
    if (session.call_id > 0) {
        eXosip_lock(m_sip_ctx_);
        eXosip_call_terminate(m_sip_ctx_, session.call_id, session.dialog_id);
        eXosip_unlock(m_sip_ctx_);
    }

    // 移除会话
    m_playback_sessions_.erase(it);

    LOGI("回放会话已停止: %s", session_id);
    return ret;
}

auto sip_server::get_playback_sessions() const -> std::vector<std::string> {
    std::vector<std::string> sessions;
    sessions.reserve(m_playback_sessions_.size());

    for (const auto& session_id : m_playback_sessions_ | std::views::keys) {
        sessions.emplace_back(session_id);
    }
    return sessions;
}

// ========== 回放相关私有方法实现 ==========
auto sip_server::generate_ssrc() -> std::string {
    static int sequence = 0;
    char ssrc[16];
    snprintf(ssrc, sizeof(ssrc), "1%03d%04d%02d", 402, 1, ++sequence % 100);
    return std::string{ssrc};
}

auto sip_server::build_playback_sdp(const char* device_id, const char* start_time,
                                    const char* end_time, const char* ssrc) const -> std::string {
    if (!device_id || !start_time || !end_time || !ssrc) {
        LOGE("build_playback_sdp: 输入参数无效");
        return "";
    }

    char sdp[2048];
    snprintf(sdp, sizeof(sdp),
             "v=0\r\n"
             "o=%s 0 0 IN IP4 %s\r\n"
             "s=Playback\r\n"
             "u=%s:0\r\n"
             "c=IN IP4 %s\r\n"
             "t=0 0\r\n"
             "m=video %d TCP/RTP/AVP 96 98 97\r\n"
             "a=recvonly\r\n"
             "a=rtpmap:96 PS/90000\r\n"
             "a=rtpmap:98 H264/90000\r\n"
             "a=rtpmap:97 MPEG4/90000\r\n"
             "a=setup:passive\r\n"
             "a=connection:new\r\n"
             "y=%s\r\n"
             "f=v/////a/1/8/1\r\n",
             m_info_->get_sip_id(), m_info_->get_ip(),
             device_id, m_info_->get_ip(),
             m_info_->get_rtp_port(), ssrc);

    return std::string{sdp};
}

auto sip_server::request_playback_invite(const char* device_id, const char* start_time,
                                         const char* end_time) const -> int {
    if (!device_id || !start_time || !end_time) {
        LOGE("request_playback_invite: 输入参数无效");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    const std::string ssrc = generate_ssrc();
    const std::string sdp = build_playback_sdp(device_id, start_time, end_time, ssrc.c_str());
    if (sdp.empty()) {
        LOGE("构建回放SDP失败");
        return -1;
    }

    char from[512], to[512], subject[256];
    snprintf(from, sizeof(from), "sip:%s@%s:%d",
             m_info_->get_sip_id(), m_info_->get_ip(), m_info_->get_port());

    snprintf(to, sizeof(to), "sip:%s@%s:%d",
             device_id, device_info->parent_ip.c_str(), device_info->parent_port);
    snprintf(subject, sizeof(subject), "%s:0,%s", device_id, ssrc.c_str());

    osip_message_t* msg = nullptr;
    if (const int ret = eXosip_call_build_initial_invite(m_sip_ctx_, &msg, to, from, nullptr, nullptr); ret != 0) {
        LOGE("构建回放INVITE失败: %d", ret);
        return -1;
    }

    osip_message_set_body(msg, sdp.c_str(), sdp.length());
    osip_message_set_content_type(msg, "application/sdp");
    osip_message_set_header(msg, "Subject", subject);

    char session_exp[128];
    snprintf(session_exp, sizeof(session_exp), "%i;refresher=uac", m_info_->get_timeout());
    osip_message_set_header(msg, "Session-Expires", session_exp);
    osip_message_set_supported(msg, "timer");

    const int call_id = eXosip_call_send_initial_invite(m_sip_ctx_, msg);
    if (call_id > 0) {
        LOGI("回放INVITE发送成功: CallID=%d, SSRC=%s", call_id, ssrc.c_str());
        return call_id;
    }
    LOGE("回放INVITE发送失败: %d", call_id);
    return -1;
}

auto sip_server::send_playback_control(const char* device_id, const char* session_id, playback_control control,
                                       const char* range, const char* scale) const -> int {
    if (!device_id || !session_id) {
        LOGE("send_playback_control: 输入参数无效");
        return -1;
    }

    char xml_body[1024];
    long sn = random() % 10000 + 1;

    const char* cmd_name = nullptr;
    switch (control) {
    case playback_control::play:
        cmd_name = "PLAY";
        break;
    case playback_control::pause:
        cmd_name = "PAUSE";
        break;
    case playback_control::stop:
        cmd_name = "TEARDOWN";
        break;
    case playback_control::speed:
        cmd_name = "SCALE";
        break;
    case playback_control::seek:
        cmd_name = "SEEK";
        break;
    }

    if (control == playback_control::seek && range) {
        snprintf(xml_body, sizeof(xml_body),
                 "<?xml version=\"1.0\"?>\r\n"
                 "<Control>\r\n"
                 "<CmdType>PlaybackControl</CmdType>\r\n"
                 "<SN>%ld</SN>\r\n"
                 "<DeviceID>%s</DeviceID>\r\n"
                 "<PlayCmd>%s</PlayCmd>\r\n"
                 "<Range>%s</Range>\r\n"
                 "</Control>",
                 sn, device_id, cmd_name, range);
    }
    else if (control == playback_control::speed && scale) {
        snprintf(xml_body, sizeof(xml_body),
                 "<?xml version=\"1.0\"?>\r\n"
                 "<Control>\r\n"
                 "<CmdType>PlaybackControl</CmdType>\r\n"
                 "<SN>%ld</SN>\r\n"
                 "<DeviceID>%s</DeviceID>\r\n"
                 "<PlayCmd>%s</PlayCmd>\r\n"
                 "<Scale>%s</Scale>\r\n"
                 "</Control>",
                 sn, device_id, cmd_name, scale);
    }
    else {
        snprintf(xml_body, sizeof(xml_body),
                 "<?xml version=\"1.0\"?>\r\n"
                 "<Control>\r\n"
                 "<CmdType>PlaybackControl</CmdType>\r\n"
                 "<SN>%ld</SN>\r\n"
                 "<DeviceID>%s</DeviceID>\r\n"
                 "<PlayCmd>%s</PlayCmd>\r\n"
                 "</Control>",
                 sn, device_id, cmd_name);
    }

    LOGI("发送回放控制: Device=%s, Session=%s, Command=%s", device_id, session_id, cmd_name);
    return send_sip_message(device_id, xml_body);
}

auto sip_server::handle_playback_info(const eXosip_event_t* evtp) -> void {
    osip_body_t* body = nullptr;
    osip_message_get_body(evtp->request, 0, &body);

    if (!body) {
        return;
    }

    char status[64] = {};
    char time[64] = {};

    if (parse_xml(body->body, "<PlayStatus>", "</PlayStatus>", status, sizeof(status)) == 0) {
        LOGI("回放状态: %s", status);
    }

    if (parse_xml(body->body, "<Time>", "</Time>", time, sizeof(time)) == 0) {
        LOGI("回放时间: %s", time);
    }

    // 可以根据状态更新相应的回放会话信息
    // 这里可以添加更多的状态处理逻辑
}

// ========== 文件下载接口实现 ==========
auto sip_server::set_download_root_path(const char* path) -> void {
    if (!path) {
        LOGE("set_download_root_path: 路径参数为空");
        return;
    }

    std::lock_guard lock(m_download_mutex_);
    m_download_root_path_ = path;
    std::filesystem::create_directories(m_download_root_path_);
    LOGI("设置下载根目录: %s", m_download_root_path_.c_str());
}

auto sip_server::generate_download_session_id() -> std::string {
    static int sequence = 0;
    char session_id[32];
    snprintf(session_id, sizeof(session_id), "DL%08d%04d",
             static_cast<int>(time(nullptr)), ++sequence % 10000);
    return std::string{session_id};
}

auto sip_server::request_file_download(const char* device_id, const char* start_time,
                                       const char* end_time, const char* local_path) -> std::string {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return "";
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return "";
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return "";
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return "";
        }
    }

    // 生成下载会话ID
    std::string session_id = generate_download_session_id();

    // 创建下载会话
    download_session session;
    session.session_id = session_id;
    session.device_id = device_id;
    session.start_time = start_time;
    session.end_time = end_time;
    session.status = download_status::pending;
    session.method = download_method::http;
    session.file_size = 0;
    session.downloaded_size = 0;
    session.last_activity = std::chrono::steady_clock::now();

    // 设置本地保存路径
    if (local_path && strlen(local_path) > 0) {
        session.local_save_path = local_path;
    }
    else {
        // 生成默认文件名
        std::string filename = std::string(device_id) + "_" +
            std::string(start_time) + "_" +
            std::string(end_time) + ".mp4";

        // 替换文件名中的特殊字符
        std::ranges::replace(filename, ':', '-');
        std::ranges::replace(filename, 'T', '_');

        session.local_save_path = m_download_root_path_ + filename;
    }

    // 保存会话
    {
        std::lock_guard lock(m_download_mutex_);
        m_download_sessions_.emplace(session_id, std::move(session));
    }

    // 请求下载信息
    if (request_download_info(device_id, start_time, end_time) != 0) {
        LOGE("请求下载信息失败");
        std::lock_guard lock(m_download_mutex_);
        m_download_sessions_.erase(session_id);
        return "";
    }

    LOGI("文件下载请求已创建，会话ID: %s", session_id.c_str());
    return session_id;
}

auto sip_server::request_download_info(const char* device_id, const char* start_time,
                                       const char* end_time) const -> int {
    if (!device_id || !start_time || !end_time) {
        LOGE("request_download_info: 输入参数无效");
        return -1;
    }

    char xml_body[1024];
    const long sn = random() % 10000 + 1;

    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\"?>\r\n"
             "<Query>\r\n"
             "<CmdType>DownloadInfo</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "<StartTime>%s</StartTime>\r\n"
             "<EndTime>%s</EndTime>\r\n"
             "<Secrecy>0</Secrecy>\r\n"
             "<Type>all</Type>\r\n"
             "</Query>",
             sn, device_id, start_time, end_time);

    LOGI("请求下载信息: Device=%s, Time=%s~%s", device_id, start_time, end_time);
    return send_sip_message(device_id, xml_body);
}

auto sip_server::parse_download_info_response(const char* xml) -> void {
    if (!xml || strlen(xml) == 0) {
        LOGE("parse_download_info_response: 输入XML为空");
        return;
    }

    std::string utf8_xml = gb2312_to_utf8(xml);
    if (utf8_xml.empty()) {
        LOGE("下载信息XML编码转换失败");
        return;
    }

    XMLDocument doc;
    if (XMLError err = doc.Parse(utf8_xml.c_str()); err != XML_SUCCESS) {
        LOGE("解析DownloadInfo XML失败: %s", doc.ErrorName());
        return;
    }

    XMLElement* root = doc.RootElement();
    if (!root || strcmp(root->Name(), "Response") != 0) {
        LOGE("无效的DownloadInfo响应");
        return;
    }

    XMLElement* device_id_elem = root->FirstChildElement("DeviceID");
    if (!device_id_elem || !device_id_elem->GetText()) {
        LOGE("DownloadInfo响应缺少DeviceID");
        return;
    }
    std::string device_id = device_id_elem->GetText();

    XMLElement* download_list = root->FirstChildElement("DownloadList");
    if (!download_list) {
        LOGI("设备%s没有可下载的文件", device_id.c_str());
        return;
    }

    std::lock_guard lock(m_download_mutex_);
    for (XMLElement* item = download_list->FirstChildElement("Item");
         item != nullptr; item = item->NextSiblingElement("Item")) {
        std::string file_name, file_path, download_url, start_time, end_time;
        uint64_t file_size = 0;

        auto get_text = [](const XMLElement* elem) -> std::string {
            return (elem && elem->GetText()) ? elem->GetText() : "";
        };

        file_name = get_text(item->FirstChildElement("FileName"));
        file_path = get_text(item->FirstChildElement("FilePath"));
        download_url = get_text(item->FirstChildElement("DownloadURL"));
        start_time = get_text(item->FirstChildElement("StartTime"));
        end_time = get_text(item->FirstChildElement("EndTime"));

        if (XMLElement* size_elem = item->FirstChildElement("FileSize");
            size_elem && size_elem->GetText()) {
            try {
                file_size = std::stoull(size_elem->GetText());
            }
            catch (const std::exception& e) {
                LOGE("文件大小解析失败: %s", e.what());
                file_size = 0;
            }
        }

        LOGI("发现可下载文件: %s (%lu bytes)", file_name.c_str(), file_size);

        // 查找匹配的下载会话并启动下载
        for (auto& [session_id, session] : m_download_sessions_) {
            if (session.device_id == device_id &&
                session.start_time == start_time &&
                session.end_time == end_time &&
                session.status == download_status::pending) {
                // 更新会话信息
                session.file_name = file_name;
                session.file_path = file_path;
                session.download_url = download_url;
                session.file_size = file_size;
                session.status = download_status::downloading;
                session.start_download_time = std::chrono::steady_clock::now();

                // 确定下载方法
                if (download_url.find("http") == 0) {
                    session.method = download_method::http;
                }
                else if (download_url.find("ftp") == 0) {
                    session.method = download_method::ftp;
                }
                else {
                    session.method = download_method::direct;
                }

                LOGI("启动文件下载: %s -> %s", download_url.c_str(), session.local_save_path.c_str());

                // 启动下载线程
                session.download_thread = std::make_unique<std::thread>([this, session_id]() {
                    auto it = m_download_sessions_.find(session_id);
                    if (it != m_download_sessions_.end()) {
                        start_file_download(it->second);
                    }
                });

                break;
            }
        }
    }
}

auto sip_server::start_file_download(const download_session& session) -> void {
    LOGI("开始下载文件: %s", session.file_name.c_str());

    bool success = false;
    switch (session.method) {
    case download_method::http:
        success = download_file_http(const_cast<download_session&>(session));
        break;
    case download_method::ftp:
        success = download_file_ftp(const_cast<download_session&>(session));
        break;
    case download_method::direct:
        LOGI("直接传输模式暂未实现");
        success = false;
        break;
    }

    complete_download(session.session_id, success);
}

// libcurl回调函数
static auto download_write_callback(const void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
    const size_t total_size = size * nmemb;

    if (const auto file = static_cast<std::ofstream*>(userp); file && file->is_open()) {
        file->write(static_cast<const char*>(contents), static_cast<long>(total_size));
        return total_size;
    }
    return 0;
}

static auto download_progress_callback([[maybe_unused]] void* clientp, [[maybe_unused]] curl_off_t dltotal,
                                       [[maybe_unused]] curl_off_t dlnow,
                                       [[maybe_unused]] curl_off_t ultotal, [[maybe_unused]] curl_off_t ulnow) -> int {
    // 进度回调，可以在这里更新下载进度
    return 0;
}

auto sip_server::download_file_http(download_session& session) -> bool {
    LOGI("开始HTTP下载: %s", session.download_url.c_str());

    // 确保目标目录存在
    std::filesystem::path local_path(session.local_save_path);
    create_directories(local_path.parent_path());

    // 打开文件
    std::ofstream file(session.local_save_path, std::ios::binary);
    if (!file.is_open()) {
        LOGE("无法创建文件: %s", session.local_save_path.c_str());
        return false;
    }

    // 初始化libcurl
    CURL* curl = curl_easy_init();
    if (!curl) {
        LOGE("libcurl初始化失败");
        file.close();
        return false;
    }

    // 设置curl选项
    curl_easy_setopt(curl, CURLOPT_URL, session.download_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, download_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3600L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, download_progress_callback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, this);

    // 执行下载
    CURLcode res = curl_easy_perform(curl);

    // 获取响应信息
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_off_t downloaded;
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &downloaded);

    // 清理
    curl_easy_cleanup(curl);
    file.close();

    bool success = (res == CURLE_OK && response_code == 200);

    if (success) {
        LOGI("HTTP下载成功: %s (%ld bytes)", session.file_name.c_str(), downloaded);

        std::lock_guard lock(m_download_mutex_);
        if (auto it = m_download_sessions_.find(session.session_id); it != m_download_sessions_.end()) {
            it->second.downloaded_size = downloaded;
        }
    }
    else {
        LOGE("HTTP下载失败: %s (curl错误: %s, HTTP状态: %ld)",
             session.file_name.c_str(), curl_easy_strerror(res), response_code);
        std::filesystem::remove(session.local_save_path);
    }

    return success;
}

auto sip_server::download_file_ftp(download_session& session) -> bool {
    LOGI("开始FTP下载: %s", session.download_url.c_str());

    std::filesystem::path local_path(session.local_save_path);
    create_directories(local_path.parent_path());

    std::ofstream file(session.local_save_path, std::ios::binary);
    if (!file.is_open()) {
        LOGE("无法创建文件: %s", session.local_save_path.c_str());
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        LOGE("libcurl初始化失败");
        file.close();
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, session.download_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, download_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3600L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);

    curl_off_t downloaded;
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &downloaded);

    curl_easy_cleanup(curl);
    file.close();

    bool success = (res == CURLE_OK);

    if (success) {
        LOGI("FTP下载成功: %s (%ld bytes)", session.file_name.c_str(), downloaded);

        std::lock_guard lock(m_download_mutex_);
        if (auto it = m_download_sessions_.find(session.session_id); it != m_download_sessions_.end()) {
            it->second.downloaded_size = downloaded;
        }
    }
    else {
        LOGE("FTP下载失败: %s (curl错误: %s)", session.file_name.c_str(), curl_easy_strerror(res));
        std::filesystem::remove(session.local_save_path);
    }

    return success;
}

auto sip_server::update_download_progress(const std::string& session_id, uint64_t downloaded) -> void {
    std::lock_guard lock(m_download_mutex_);

    if (const auto it = m_download_sessions_.find(session_id); it != m_download_sessions_.end()) {
        it->second.downloaded_size = downloaded;
        it->second.last_activity = std::chrono::steady_clock::now();

        if (it->second.progress_callback) {
            it->second.progress_callback(it->second);
        }

        if (it->second.file_size > 0) {
            const double progress = static_cast<double>(downloaded) / static_cast<double>(it->second.file_size) * 100.0;
            LOGI("下载进度: %s - %.2f%%", session_id.c_str(), progress);
        }
    }
}

auto sip_server::complete_download(const std::string& session_id, bool success) -> void {
    std::lock_guard lock(m_download_mutex_);

    if (const auto it = m_download_sessions_.find(session_id); it != m_download_sessions_.end()) {
        it->second.status = success ? download_status::completed : download_status::failed;
        it->second.last_activity = std::chrono::steady_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            it->second.last_activity - it->second.start_download_time).count();

        if (success) {
            LOGI("文件下载完成: %s -> %s (用时: %ld秒)",
                 it->second.file_name.c_str(), it->second.local_save_path.c_str(), duration);
        }
        else {
            LOGE("文件下载失败: %s (用时: %ld秒)", it->second.file_name.c_str(), duration);
        }

        if (it->second.progress_callback) {
            it->second.progress_callback(it->second);
        }
    }
}

auto sip_server::cancel_download(const char* session_id) -> int {
    if (!session_id) {
        return -1;
    }

    std::lock_guard lock(m_download_mutex_);

    auto it = m_download_sessions_.find(session_id);
    if (it == m_download_sessions_.end()) {
        LOGE("下载会话不存在: %s", session_id);
        return -1;
    }

    LOGI("取消下载: %s", session_id);
    it->second.status = download_status::cancelled;

    return 0;
}

auto sip_server::get_download_progress(const char* session_id) const -> std::pair<uint64_t, uint64_t> {
    if (!session_id) {
        return {0, 0};
    }

    std::lock_guard lock(m_download_mutex_);

    auto it = m_download_sessions_.find(session_id);
    if (it != m_download_sessions_.end()) {
        return {it->second.downloaded_size, it->second.file_size};
    }

    return {0, 0};
}

auto sip_server::get_download_status(const char* session_id) const -> download_status {
    if (!session_id) {
        return download_status::failed;
    }

    std::lock_guard lock(m_download_mutex_);

    auto it = m_download_sessions_.find(session_id);
    if (it != m_download_sessions_.end()) {
        return it->second.status;
    }

    return download_status::failed;
}

auto sip_server::list_downloads() const -> std::vector<std::string> {
    std::lock_guard lock(m_download_mutex_);

    std::vector<std::string> sessions;
    sessions.reserve(m_download_sessions_.size());

    for (const auto& session_id : m_download_sessions_ | std::views::keys) {
        sessions.emplace_back(session_id);
    }

    return sessions;
}

auto sip_server::handle_download_response(const eXosip_event_t* evtp) -> void {
    osip_body_t* body = nullptr;
    osip_message_get_body(evtp->request, 0, &body);

    if (!body) {
        return;
    }

    char status[64] = {};
    char progress[64] = {};
    char session_id[64] = {};

    if (parse_xml(body->body, "<Status>", "</Status>", status, sizeof(status)) == 0) {
        LOGI("下载状态: %s", status);
    }

    if (parse_xml(body->body, "<Progress>", "</Progress>", progress, sizeof(progress)) == 0) {
        LOGI("下载进度: %s", progress);
    }

    if (parse_xml(body->body, "<SessionID>", "</SessionID>", session_id, sizeof(session_id)) == 0) {
        // 可以根据设备反馈更新下载状态
        LOGI("收到下载状态更新: SessionID=%s", session_id);
    }
}

// ========== 抓拍功能接口实现 ==========
auto sip_server::set_snapshot_root_path(const char* path) -> void {
    if (!path) {
        LOGE("set_snapshot_root_path: 路径参数为空");
        return;
    }

    std::lock_guard lock(m_snapshot_mutex_);
    m_snapshot_root_path_ = path;
    std::filesystem::create_directories(m_snapshot_root_path_);
    LOGI("设置抓拍根目录: %s", m_snapshot_root_path_.c_str());
}

auto sip_server::generate_snapshot_session_id() -> std::string {
    static int sequence = 0;
    char session_id[32];
    snprintf(session_id, sizeof(session_id), "SP%08d%04d",
             static_cast<int>(time(nullptr)), ++sequence % 10000);
    return std::string{session_id};
}

auto sip_server::request_snapshot(const char* device_id, uint32_t quality,
                                  const char* format, const char* local_path) -> std::string {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return "";
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return "";
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return "";
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return "";
        }
    }

    // 生成抓拍会话ID
    std::string session_id = generate_snapshot_session_id();

    // 创建抓拍会话
    snapshot_session session;
    session.session_id = session_id;
    session.device_id = device_id;
    session.status = snapshot_status::pending;
    session.quality = quality;
    session.format = format ? format : "JPEG";
    session.request_time = std::chrono::steady_clock::now();
    session.last_activity = session.request_time;

    // 设置本地保存路径
    if (local_path && strlen(local_path) > 0) {
        session.local_save_path = local_path;
    }
    else {
        // 生成默认文件名
        const auto now = std::chrono::system_clock::now();
        const auto time_t = std::chrono::system_clock::to_time_t(now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&time_t));

        const std::string filename = std::string(device_id) + "_" + timestamp +
            "." + (session.format == "JPEG" ? "jpg" : "png");
        session.local_save_path = m_snapshot_root_path_ + filename;
    }

    // 保存会话
    {
        std::lock_guard lock(m_snapshot_mutex_);
        m_snapshot_sessions_[session_id] = std::move(session);
    }

    // 发送抓拍命令
    char xml_body[1024];
    const long sn = random() % 10000 + 1;

    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\"?>\r\n"
             "<Control>\r\n"
             "<CmdType>DeviceControl</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "<SnapShotConfig>\r\n"
             "<Quality>%d</Quality>\r\n"
             "<Format>%s</Format>\r\n"
             "<SessionID>%s</SessionID>\r\n"
             "</SnapShotConfig>\r\n"
             "</Control>",
             sn, device_id, quality, session.format.c_str(), session_id.c_str());

    if (send_sip_message(device_id, xml_body) != 0) {
        LOGE("发送抓拍命令失败");
        std::lock_guard lock(m_snapshot_mutex_);
        m_snapshot_sessions_.erase(session_id);
        return "";
    }

    LOGI("抓拍请求已创建: Device=%s, Quality=%d, Format=%s, SessionID=%s",
         device_id, quality, session.format.c_str(), session_id.c_str());
    return session_id;
}

auto sip_server::get_snapshot_status(const char* session_id) const -> snapshot_status {
    if (!session_id) {
        return snapshot_status::failed;
    }

    std::lock_guard lock(m_snapshot_mutex_);
    auto it = m_snapshot_sessions_.find(session_id);
    if (it != m_snapshot_sessions_.end()) {
        return it->second.status;
    }
    return snapshot_status::failed;
}

auto sip_server::list_snapshots() const -> std::vector<std::string> {
    std::lock_guard lock(m_snapshot_mutex_);

    std::vector<std::string> sessions;
    sessions.reserve(m_snapshot_sessions_.size());

    for (const auto& session_id : m_snapshot_sessions_ | std::views::keys) {
        sessions.emplace_back(session_id);
    }

    return sessions;
}

auto sip_server::parse_snapshot_response(const char* xml) -> void {
    if (!xml || strlen(xml) == 0) {
        LOGE("parse_snapshot_response: 输入XML为空");
        return;
    }

    std::string utf8_xml = gb2312_to_utf8(xml);
    if (utf8_xml.empty()) {
        LOGE("抓拍响应XML编码转换失败");
        return;
    }

    XMLDocument doc;
    if (XMLError err = doc.Parse(utf8_xml.c_str()); err != XML_SUCCESS) {
        LOGE("解析抓拍响应XML失败: %s", doc.ErrorName());
        return;
    }

    char session_id[64] = {};
    char result[64] = {};

    if (parse_xml(xml, "<SessionID>", "</SessionID>", session_id, sizeof(session_id)) == 0 &&
        parse_xml(xml, "<Result>", "</Result>", result, sizeof(result)) == 0) {
        std::lock_guard lock(m_snapshot_mutex_);
        auto it = m_snapshot_sessions_.find(session_id);
        if (it != m_snapshot_sessions_.end()) {
            if (strcmp(result, "OK") == 0) {
                it->second.status = snapshot_status::capturing;
                LOGI("抓拍开始: SessionID=%s", session_id);
            }
            else {
                it->second.status = snapshot_status::failed;
                LOGE("抓拍失败: SessionID=%s, 原因=%s", session_id, result);
            }
            it->second.last_activity = std::chrono::steady_clock::now();
        }
    }
}

auto sip_server::handle_snapshot_notify(const eXosip_event_t* evtp) -> void {
    osip_body_t* body = nullptr;
    osip_message_get_body(evtp->request, 0, &body);

    if (!body) {
        return;
    }

    char session_id[64] = {};
    char image_path[256] = {};
    char status[32] = {};

    if (parse_xml(body->body, "<SessionID>", "</SessionID>", session_id, sizeof(session_id)) == 0 &&
        parse_xml(body->body, "<ImagePath>", "</ImagePath>", image_path, sizeof(image_path)) == 0 &&
        parse_xml(body->body, "<Status>", "</Status>", status, sizeof(status)) == 0) {
        LOGI("收到抓拍通知: SessionID=%s, Path=%s, Status=%s", session_id, image_path, status);

        std::lock_guard lock(m_snapshot_mutex_);
        auto it = m_snapshot_sessions_.find(session_id);
        if (it != m_snapshot_sessions_.end()) {
            if (strcmp(status, "Complete") == 0) {
                it->second.status = snapshot_status::completed;
                it->second.image_path = image_path;
                LOGI("抓拍完成: SessionID=%s -> %s", session_id, image_path);
            }
            else {
                it->second.status = snapshot_status::failed;
                LOGE("抓拍失败: SessionID=%s", session_id);
            }
            it->second.last_activity = std::chrono::steady_clock::now();
        }
    }
}

// ========== 设备配置功能实现 ==========
auto sip_server::device_config_type_to_string(device_config_type type) -> std::string {
    switch (type) {
    case device_config_type::basic_param: return "BasicParam";
    case device_config_type::video_param: return "VideoParam";
    case device_config_type::audio_param: return "AudioParam";
    case device_config_type::network_param: return "NetworkParam";
    case device_config_type::ptz_param: return "PTZParam";
    case device_config_type::record_param: return "RecordParam";
    case device_config_type::alarm_param: return "AlarmParam";
    default: return "BasicParam";
    }
}

auto sip_server::request_device_config(const char* device_id, device_config_type config_type) const -> int {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    std::string config_type_str = device_config_type_to_string(config_type);

    char xml_body[1024];
    long sn = random() % 10000 + 1;

    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\"?>\r\n"
             "<Query>\r\n"
             "<CmdType>ConfigDownload</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "<ConfigType>%s</ConfigType>\r\n"
             "</Query>",
             sn, device_id, config_type_str.c_str());

    LOGI("请求设备配置: Device=%s, Type=%s", device_id, config_type_str.c_str());
    return send_sip_message(device_id, xml_body);
}

auto sip_server::set_device_config(const char* device_id, device_config_type config_type,
                                   const char* config_xml) const -> int {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    std::string config_type_str = device_config_type_to_string(config_type);

    char xml_body[2048];
    long sn = random() % 10000 + 1;

    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\"?>\r\n"
             "<Control>\r\n"
             "<CmdType>DeviceConfig</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "<ConfigType>%s</ConfigType>\r\n"
             "<ConfigData><![CDATA[%s]]></ConfigData>\r\n"
             "</Control>",
             sn, device_id, config_type_str.c_str(), config_xml);

    LOGI("设置设备配置: Device=%s, Type=%s", device_id, config_type_str.c_str());
    return send_sip_message(device_id, xml_body);
}

auto sip_server::get_device_config(const char* device_id, device_config_type config_type) const -> std::string {
    if (!device_id) {
        return "";
    }

    std::lock_guard lock(m_config_mutex_);

    std::string key = std::string(device_id) + "_" + std::to_string(static_cast<int>(config_type));
    auto it = m_device_configs_.find(key);
    if (it != m_device_configs_.end()) {
        return it->second.config_data;
    }

    return "";
}

auto sip_server::parse_device_config_response(const char* xml) -> void {
    if (!xml || strlen(xml) == 0) {
        LOGE("parse_device_config_response: 输入XML为空");
        return;
    }

    std::string utf8_xml = gb2312_to_utf8(xml);
    if (utf8_xml.empty()) {
        LOGE("设备配置响应XML编码转换失败");
        return;
    }

    XMLDocument doc;
    if (XMLError err = doc.Parse(utf8_xml.c_str()); err != XML_SUCCESS) {
        LOGE("解析设备配置响应XML失败: %s", doc.ErrorName());
        return;
    }

    char device_id[64] = {};
    char config_type_str[64] = {};
    char config_data[2048] = {};

    if (parse_xml(xml, "<DeviceID>", "</DeviceID>", device_id, sizeof(device_id)) == 0 &&
        parse_xml(xml, "<ConfigType>", "</ConfigType>", config_type_str, sizeof(config_type_str)) == 0 &&
        parse_xml(xml, "<ConfigData>", "</ConfigData>", config_data, sizeof(config_data)) == 0) {
        LOGI("收到设备配置响应: Device=%s, Type=%s", device_id, config_type_str);

        device_config config;
        config.device_id = device_id;
        config.config_data = config_data;
        config.last_update = std::chrono::steady_clock::now();

        // 根据配置类型字符串确定枚举值
        if (strcmp(config_type_str, "BasicParam") == 0) {
            config.config_type = device_config_type::basic_param;
        }
        else if (strcmp(config_type_str, "VideoParam") == 0) {
            config.config_type = device_config_type::video_param;
        }
        else if (strcmp(config_type_str, "AudioParam") == 0) {
            config.config_type = device_config_type::audio_param;
        }
        else if (strcmp(config_type_str, "NetworkParam") == 0) {
            config.config_type = device_config_type::network_param;
        }
        else if (strcmp(config_type_str, "PTZParam") == 0) {
            config.config_type = device_config_type::ptz_param;
        }
        else if (strcmp(config_type_str, "RecordParam") == 0) {
            config.config_type = device_config_type::record_param;
        }
        else if (strcmp(config_type_str, "AlarmParam") == 0) {
            config.config_type = device_config_type::alarm_param;
        }
        else {
            config.config_type = device_config_type::basic_param;
            LOGI("config_type_str is other type");
        }

        std::lock_guard lock(m_config_mutex_);
        std::string key = std::string(device_id) + "_" + std::to_string(static_cast<int>(config.config_type));
        m_device_configs_[key] = config;

        LOGI("设备配置已保存: %s", key.c_str());
    }
}

auto sip_server::handle_device_config_notify(const eXosip_event_t* evtp) -> void {
    osip_body_t* body = nullptr;
    osip_message_get_body(evtp->request, 0, &body);

    if (!body || !body->body) {
        LOGE("handle_device_config_notify: 消息体为空");
        return;
    }

    LOGI("收到设备配置通知");

    char device_id[64] = {};
    char config_type_str[64] = {};
    char result[64] = {};

    if (parse_xml(body->body, "<DeviceID>", "</DeviceID>", device_id, sizeof(device_id)) != 0) {
        LOGE("解析DeviceID失败");
        return;
    }

    if (parse_xml(body->body, "<ConfigType>", "</ConfigType>", config_type_str, sizeof(config_type_str)) != 0) {
        LOGE("解析ConfigType失败");
        return;
    }

    if (parse_xml(body->body, "<Result>", "</Result>", result, sizeof(result)) == 0) {
        LOGI("设备配置通知: Device=%s, Type=%s, Result=%s", device_id, config_type_str, result);

        if (strcmp(result, "OK") == 0) {
            char config_data[2048] = {};
            if (parse_xml(body->body, "<ConfigData>", "</ConfigData>", config_data, sizeof(config_data)) == 0) {
                // 更新本地配置缓存
                device_config config;
                config.device_id = device_id;
                config.config_data = config_data;
                config.last_update = std::chrono::steady_clock::now();

                // 确定配置类型
                if (strcmp(config_type_str, "BasicParam") == 0) {
                    config.config_type = device_config_type::basic_param;
                }
                else if (strcmp(config_type_str, "VideoParam") == 0) {
                    config.config_type = device_config_type::video_param;
                }
                else if (strcmp(config_type_str, "AudioParam") == 0) {
                    config.config_type = device_config_type::audio_param;
                }
                else if (strcmp(config_type_str, "NetworkParam") == 0) {
                    config.config_type = device_config_type::network_param;
                }
                else if (strcmp(config_type_str, "PTZParam") == 0) {
                    config.config_type = device_config_type::ptz_param;
                }
                else if (strcmp(config_type_str, "RecordParam") == 0) {
                    config.config_type = device_config_type::record_param;
                }
                else if (strcmp(config_type_str, "AlarmParam") == 0) {
                    config.config_type = device_config_type::alarm_param;
                }
                else {
                    config.config_type = device_config_type::basic_param;
                    LOGI("config_type_str is other type");
                }

                std::lock_guard lock(m_config_mutex_);
                const std::string key = std::string(device_id) + "_" + std::to_string(
                    static_cast<int>(config.config_type));
                m_device_configs_[key] = config;

                LOGI("设备配置通知已更新缓存: %s", key.c_str());
            }
        }
        else {
            LOGE("设备配置操作失败: Device=%s, Type=%s, Result=%s", device_id, config_type_str, result);
        }
    }
    else {
        // 可能是配置变更的主动通知
        char config_data[2048] = {};
        if (parse_xml(body->body, "<ConfigData>", "</ConfigData>", config_data, sizeof(config_data)) == 0) {
            LOGI("收到设备配置变更通知: Device=%s, Type=%s", device_id, config_type_str);

            // 保存到通知消息列表
            notify_message msg;
            msg.device_id = device_id;
            msg.notify_type = std::string("ConfigChange_") + config_type_str;
            msg.content = body->body;
            msg.receive_time = std::chrono::steady_clock::now();

            std::lock_guard notify_lock(m_notify_mutex_);
            m_notify_messages_.push_back(msg);

            if (m_notify_messages_.size() > 1000) {
                m_notify_messages_.erase(m_notify_messages_.begin());
            }
        }
    }
}

// ========== 通知消息功能实现 ==========
auto sip_server::handle_notify_message(const eXosip_event_t* evtp) -> void {
    osip_body_t* body = nullptr;
    osip_message_get_body(evtp->request, 0, &body);

    if (!body) {
        return;
    }

    parse_notify_content(body->body);
}

auto sip_server::parse_notify_content(const char* xml) -> void {
    if (!xml || strlen(xml) == 0) {
        return;
    }

    char device_id[64] = {};
    char notify_type[64] = {};

    if (parse_xml(xml, "<DeviceID>", "</DeviceID>", device_id, sizeof(device_id)) == 0 &&
        parse_xml(xml, "<NotifyType>", "</NotifyType>", notify_type, sizeof(notify_type)) == 0) {
        notify_message msg;
        msg.device_id = device_id;
        msg.notify_type = notify_type;
        msg.content = xml;
        msg.receive_time = std::chrono::steady_clock::now();

        std::lock_guard lock(m_notify_mutex_);
        m_notify_messages_.push_back(msg);

        // 限制消息数量，避免内存泄漏
        if (m_notify_messages_.size() > 1000) {
            m_notify_messages_.erase(m_notify_messages_.begin());
        }

        LOGI("收到通知消息: Device=%s, Type=%s", device_id, notify_type);
    }
}

auto sip_server::get_notify_messages(const char* device_id) const -> std::vector<notify_message> {
    std::lock_guard lock(m_notify_mutex_);

    std::vector<notify_message> result;

    for (const auto& msg : m_notify_messages_) {
        if (device_id == nullptr || msg.device_id == device_id) {
            result.push_back(msg);
        }
    }

    return result;
}

auto sip_server::clear_notify_messages() -> void {
    std::lock_guard lock(m_notify_mutex_);
    m_notify_messages_.clear();
    LOGI("已清空通知消息");
}

// ========== 清理方法实现 ==========
auto sip_server::cleanup_expired_sessions() -> void {
    const auto now = std::chrono::steady_clock::now();
    int cleaned_count = 0;

    // 清理过期的回放会话
    for (auto it = m_playback_sessions_.begin(); it != m_playback_sessions_.end();) {
        const auto duration = std::chrono::duration_cast<std::chrono::minutes>(
            now - it->second.last_activity).count();

        if (duration > 60) {
            // 超过60分钟未活动
            LOGI("清理过期回放会话: %s (闲置%ld分钟)", it->first.c_str(), duration);

            if (it->second.call_id > 0) {
                eXosip_lock(m_sip_ctx_);
                int ret = eXosip_call_terminate(m_sip_ctx_, it->second.call_id, it->second.dialog_id);
                eXosip_unlock(m_sip_ctx_);

                if (ret != 0) {
                    LOGE("终止会话失败: call_id=%d, ret=%d", it->second.call_id, ret);
                }
            }

            it = m_playback_sessions_.erase(it);
            cleaned_count++;
        }
        else {
            ++it;
        }
    }

    // 清理过期的抓拍会话
    cleanup_expired_snapshots();

    if (cleaned_count > 0) {
        LOGI("已清理%d个过期回放会话", cleaned_count);
    }
}

auto sip_server::cleanup_expired_queries() const -> void {
    std::lock_guard lock(m_query_mutex_);

    const auto now = std::chrono::steady_clock::now();
    int cleaned_count = 0;

    for (auto it = m_pending_queries_.begin(); it != m_pending_queries_.end();) {
        const auto duration = std::chrono::duration_cast<std::chrono::minutes>(
            now - it->second.last_query_time).count();

        bool should_clean = false;
        std::string reason;

        if (it->second.query_complete && duration > 10) {
            should_clean = true;
            reason = "已完成查询超时";
        }
        else if (!it->second.query_complete && duration > 30) {
            should_clean = true;
            reason = "未完成查询超时";
            LOGE("设备%s的录像查询可能卡住了，强制清理", it->first.c_str());
        }

        if (should_clean) {
            LOGI("清理查询状态: %s (%s, 闲置%ld分钟)",
                 it->first.c_str(), reason.c_str(), duration);
            it = m_pending_queries_.erase(it);
            cleaned_count++;
        }
        else {
            ++it;
        }
    }

    if (cleaned_count > 0) {
        LOGI("已清理%d个过期查询状态", cleaned_count);
    }
}

auto sip_server::cleanup_expired_downloads() -> void {
    std::lock_guard lock(m_download_mutex_);

    auto now = std::chrono::steady_clock::now();
    int cleaned_count = 0;

    for (auto it = m_download_sessions_.begin(); it != m_download_sessions_.end();) {
        const auto& session = it->second;
        auto duration = std::chrono::duration_cast<std::chrono::hours>(
            now - session.last_activity).count();

        bool should_clean = false;

        // 清理条件：
        // 1. 已完成或失败的下载超过24小时
        // 2. 取消的下载超过1小时
        // 3. 挂起状态超过2小时
        if ((session.status == download_status::completed ||
            session.status == download_status::failed) && duration >= 24) {
            LOGI("已完成或失败的下载超过24小时");
            should_clean = true;
        }
        else if (session.status == download_status::cancelled && duration >= 1) {
            LOGI("取消的下载超过1小时");
            should_clean = true;
        }
        else if (session.status == download_status::pending && duration >= 2) {
            LOGI("挂起状态超过2小时");
            should_clean = true;
        }

        if (should_clean) {
            LOGI("清理过期下载会话: %s (状态: %d, 闲置: %ld小时)",
                 it->first.c_str(), static_cast<int>(session.status), duration);

            // 如果下载线程还在运行，分离线程避免阻塞
            if (it->second.download_thread && it->second.download_thread->joinable()) {
                it->second.download_thread->detach();
            }

            it = m_download_sessions_.erase(it);
            cleaned_count++;
        }
        else {
            ++it;
        }
    }

    if (cleaned_count > 0) {
        LOGI("已清理%d个过期下载会话", cleaned_count);
    }
}

auto sip_server::cleanup_expired_snapshots() -> void {
    std::lock_guard lock(m_snapshot_mutex_);

    auto now = std::chrono::steady_clock::now();
    int cleaned_count = 0;

    for (auto it = m_snapshot_sessions_.begin(); it != m_snapshot_sessions_.end();) {
        auto duration = std::chrono::duration_cast<std::chrono::hours>(
            now - it->second.last_activity).count();

        bool should_clean = false;

        // 清理条件：
        // 1. 已完成或失败的抓拍超过24小时
        // 2. 等待状态超过1小时
        if ((it->second.status == snapshot_status::completed ||
            it->second.status == snapshot_status::failed) && duration >= 24) {
            LOGI("已完成或失败的抓拍超过24小时");
            should_clean = true;
        }
        else if (it->second.status == snapshot_status::pending && duration >= 1) {
            LOGI("等待状态超过1小时");
            should_clean = true;
        }

        if (should_clean) {
            LOGI("清理过期抓拍会话: %s", it->first.c_str());
            it = m_snapshot_sessions_.erase(it);
            cleaned_count++;
        }
        else {
            ++it;
        }
    }

    if (cleaned_count > 0) {
        LOGI("已清理%d个过期抓拍会话", cleaned_count);
    }
}

auto sip_server::request_next_record_page(const std::string& device_id) const -> int {
    std::lock_guard lock(m_query_mutex_);

    auto it = m_pending_queries_.find(device_id);
    if (it == m_pending_queries_.end()) {
        LOGE("未找到设备%s的查询状态", device_id.c_str());
        return -1;
    }

    const auto& query_state = it->second;

    if (query_state.query_complete) {
        LOGI("设备%s的查询已完成，无需继续", device_id.c_str());
        return 0;
    }

    char xml_body[1024];
    long sn = random() % 10000 + 1;

    int ret = snprintf(xml_body, sizeof(xml_body),
                       "<?xml version=\"1.0\"?>\r\n"
                       "<Query>\r\n"
                       "<CmdType>RecordInfo</CmdType>\r\n"
                       "<SN>%ld</SN>\r\n"
                       "<DeviceID>%s</DeviceID>\r\n"
                       "<StartTime>%s</StartTime>\r\n"
                       "<EndTime>%s</EndTime>\r\n"
                       "<StartIndex>%d</StartIndex>\r\n"
                       "<Secrecy>0</Secrecy>\r\n"
                       "<Type>%s</Type>\r\n"
                       "</Query>",
                       sn,
                       device_id.c_str(),
                       query_state.start_time.c_str(),
                       query_state.end_time.c_str(),
                       query_state.received_count,
                       query_state.query_type.c_str());

    if (ret < 0 || ret >= static_cast<int>(sizeof(xml_body))) {
        LOGE("构建录像查询XML失败");
        return -1;
    }

    LOGI("请求下一页录像: Device=%s, StartIndex=%d", device_id.c_str(), query_state.received_count);
    return send_sip_message(device_id.c_str(), xml_body);
}

// ========== 调试和辅助方法 ==========
auto sip_server::debug_record_memory(const std::string& device_id) const -> void {
    LOGI("========== 内存调试: 设备%s ==========", device_id.c_str());

    const auto it = m_record_map_.find(device_id);
    if (it == m_record_map_.end()) {
        LOGI("设备%s不在记录映射中", device_id.c_str());
        return;
    }

    const auto& records = it->second;
    LOGI("设备%s在内存中有%zu条录像记录", device_id.c_str(), records.size());

    for (size_t i = 0; i < std::min(static_cast<size_t>(5), records.size()); ++i) {
        const auto& record = records[i];
        LOGI("录像记录%zu: %s ~ %s (%s)",
             i + 1, record.start_time.c_str(), record.end_time.c_str(), record.name.c_str());
    }

    if (records.size() > 5) {
        LOGI("... 还有%zu条记录", records.size() - 5);
    }

    LOGI("========== 内存调试结束 ==========");
}

// ========== 兼容性和扩展方法 ==========
auto sip_server::test_capability_query(const char* device_id) const -> void {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return;
        }
    }

    char xml_body[1024];
    int sn = static_cast<int>(random()) % 10000 + 1;

    // 查询设备能力
    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"
             "<Query>\r\n"
             "<CmdType>DeviceInfo</CmdType>\r\n"
             "<SN>%d</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "</Query>\r\n",
             sn, device_id);

    LOGI("查询设备能力: %s", device_id);
    if (const int tip = send_sip_message(device_id, xml_body); tip == -1) {
        LOGI(" send_sip_message error");
    }
}

auto sip_server::ptz_position_find(const char* device_id) const -> void {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return;
        }
    }

    char xml_body[1024];
    const long sn = random() % 10000 + 1;
    int horizontal = 200; // 向右移动
    int vertical = 200; // 向上移动
    int zoom = 128; // 不缩放
    int move_time = 3; // 移动3秒

    snprintf(xml_body, sizeof(xml_body),
             "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"
             "<Control>\r\n"
             "<CmdType>DeviceControl</CmdType>\r\n"
             "<SN>%ld</SN>\r\n"
             "<DeviceID>%s</DeviceID>\r\n"
             "<PTZCmd>\r\n"
             "<PTZPreciseCtrl>\r\n"
             "<Command>Move</Command>\r\n"
             "<Horizontal>%d</Horizontal>\r\n"
             "<Vertical>%d</Vertical>\r\n"
             "<Zoom>%d</Zoom>\r\n"
             "<MoveTime>%d</MoveTime>\r\n"
             "</PTZPreciseCtrl>\r\n"
             "</PTZCmd>\r\n"
             "</Control>\r\n",
             sn, device_id, horizontal, vertical, zoom, move_time);

    LOGI("发送精确PTZ控制: %s", device_id);
    int tip = send_sip_message(device_id, xml_body);
    if (tip == -1) {
        LOGI("send sip message error");
    }
}

// ========== 模块化功能测试接口 ==========
auto sip_server::test_ptz_operations(const char* device_id) const -> int {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    LOGI("开始PTZ操作测试: %s", device_id);

    // 测试基本PTZ控制
    if (send_ptz_control(device_id, ptz_command::ptz_up, 144) == -1) {
        LOGE("send_ptz_control error");
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));
    if (send_ptz_control(device_id, ptz_command::ptz_stop, 0) == -1) {
        LOGE("send_ptz_control error");
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // 测试预置位操作
    if (send_preset_control(device_id, preset_operation::set, 1) == -1) {
        LOGE("send_preset_control error");
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));

    if (send_preset_control(device_id, preset_operation::call, 1) == -1) {
        LOGE("send_preset_control error");
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // 查询PTZ位置
    if (send_ptz_position_query(device_id) == -1) {
        LOGE("send_ptz_position_query error");
    }

    LOGI("PTZ操作测试完成: %s", device_id);
    return 0;
}

auto sip_server::test_recording_operations(const char* device_id) -> int {
    if (!device_id) {
        LOGE("send_ptz_control: 设备ID为空");
        return -1;
    }

    // 检查设备是否存在（可能是子设备）
    const auto* device_info = find_device_in_tree(device_id);
    if (!device_info) {
        LOGE("设备%s不存在", device_id);
        return -1;
    }

    // 对于子设备，需要检查父设备是否在线
    if (!device_info->parent_device_id.empty()) {
        if (!is_device_online(device_info->parent_device_id.c_str())) {
            LOGE("子设备%s的父设备%s未在线", device_id, device_info->parent_device_id.c_str());
            return -1;
        }
    }
    else {
        // 根设备，检查自身是否在线
        if (!is_device_online(device_id)) {
            LOGE("设备%s未在线", device_id);
            return -1;
        }
    }

    LOGI("开始录像操作测试: %s", device_id);

    // 查询录像
    const auto start_time = "2025-09-04T12:00:00";

    if (const auto end_time = "2025-09-04T13:00:00"; request_record_query(device_id, start_time, end_time, "all") ==
        0) {
        LOGI("录像查询请求发送成功");

        // 等待查询结果
        std::this_thread::sleep_for(std::chrono::seconds(5));

        // 检查是否有录像记录
        if (const auto records = get_record_list(device_id); !records.empty()) {
            LOGI("找到%zu条录像记录", records.size());

            // 测试回放第一条记录
            const std::string session_id = start_playback(device_id,
                                                          records[0].start_time.c_str(), records[0].end_time.c_str());
            if (!session_id.empty()) {
                LOGI("回放会话创建成功: %s", session_id.c_str());

                // 等待一段时间后停止
                std::this_thread::sleep_for(std::chrono::seconds(10));
                stop_playback(session_id.c_str());
            }
        }
        else {
            LOGI("未找到录像记录");
        }
    }
    else {
        LOGE("录像查询请求失败");
        return -1;
    }

    LOGI("录像操作测试完成: %s", device_id);
    return 0;
}
