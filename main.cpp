#include "SipServer.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include "Utils/Log.h"

// 辅助函数：打印分隔线
auto print_separator(const std::string& title) -> void {
    std::cout << "\n=============== " << title << " ===============\n" << std::endl;
}

// 辅助函数：等待用户输入
auto wait_for_user_input(const std::string& prompt) -> void {
    std::cout << prompt << " (按回车键继续...)";
    std::cin.get();
}

// 辅助函数：显示设备列表（层次化）
auto display_registered_devices(const sip_server& server) -> void {
    const auto devices = server.get_registered_devices();
    if (devices.empty()) {
        std::cout << "当前无已注册设备" << std::endl;
        return;
    }

    std::cout << "设备树结构:" << std::endl;
    for (const auto& device_id : devices) {
        auto info = server.get_device_info(device_id.c_str());
        std::cout << "├─ " << device_id
            << " (" << info.name << ") - "
            << (server.is_device_online(device_id.c_str()) ? "在线" : "离线") << std::endl;

        // 获取并显示该设备的所有子设备
        auto catalog = server.get_device_catalog(device_id.c_str());
        for (size_t i = 0; i < catalog.size(); ++i) {
            const auto& child = catalog[i];
            const bool is_last = (i == catalog.size() - 1);

            const char* type_str{};
            switch (child.type) {
            case device_type::camera: type_str = "[摄像头]";
                break;
            case device_type::nvr: type_str = "[录像机]";
                break;
            case device_type::audio_out: type_str = "[音频]";
                break;
            default: type_str = "[其他]";
                break;
            }

            std::cout << "│  " << (is_last ? "└─ " : "├─ ")
                << child.device_id
                << " (" << child.name << ") "
                << type_str << " - "
                << child.model << " ["
                << child.status << "]" << std::endl;
        }
    }
}

// 辅助函数：显示所有可用的摄像头设备
auto display_all_cameras(const sip_server& server) -> void {
    const auto cameras = server.get_all_camera_devices();
    if (cameras.empty()) {
        std::cout << "当前无可用摄像头设备" << std::endl;
        return;
    }

    std::cout << "所有可用摄像头设备:" << std::endl;
    for (size_t i = 0; i < cameras.size(); ++i) {
        const auto& camera = cameras[i];
        std::cout << "  " << (i + 1) << ". " << camera.device_id
            << " (" << camera.name << ") - " << camera.model
            << " [父设备: " << camera.parent_device_id << "]" << std::endl;
    }
}

// 辅助函数：选择摄像头设备
auto select_camera_device(const sip_server& server) -> std::string {
    auto cameras = server.get_all_camera_devices();
    if (cameras.empty()) {
        std::cout << "无可用摄像头设备" << std::endl;
        return "";
    }

    if (cameras.size() == 1) {
        std::cout << "选择摄像头设备: " << cameras[0].device_id
            << " (" << cameras[0].name << ")" << std::endl;
        return cameras[0].device_id;
    }

    display_all_cameras(server);
    std::cout << "请选择摄像头设备 (1-" << cameras.size() << "): ";

    int choice;
    std::cin >> choice;
    std::cin.ignore();

    if (choice > 0 && choice <= static_cast<int>(cameras.size())) {
        const auto& selected = cameras[choice - 1];
        std::cout << "已选择: " << selected.device_id << " (" << selected.name << ")" << std::endl;
        return selected.device_id;
    }

    std::cout << "无效选择" << std::endl;
    return "";
}

// 重载选择设备函数，支持所有设备类型选择
auto select_any_device(const sip_server& server) -> std::string {
    const auto devices = server.get_registered_devices();
    if (devices.empty()) {
        std::cout << "无可用设备" << std::endl;
        return "";
    }

    // 收集所有可操作的设备（包括子设备）
    std::vector<device_info> all_devices;

    for (const auto& device_id : devices) {
        // 添加根设备
        if (auto root_info = server.get_device_info(device_id.c_str()); root_info.type == device_type::camera ||
            root_info.type == device_type::nvr) {
            all_devices.push_back(root_info);
        }

        // 添加子设备
        for (auto catalog = server.get_device_catalog(device_id.c_str()); const auto& child : catalog) {
            if (child.type == device_type::camera || child.type == device_type::nvr) {
                all_devices.push_back(child);
            }
        }
    }

    if (all_devices.empty()) {
        std::cout << "无可操作的设备" << std::endl;
        return "";
    }

    if (all_devices.size() == 1) {
        std::cout << "选择设备: " << all_devices[0].device_id
            << " (" << all_devices[0].name << ")" << std::endl;
        return all_devices[0].device_id;
    }

    std::cout << "可操作设备列表:" << std::endl;
    for (size_t i = 0; i < all_devices.size(); ++i) {
        const auto& device = all_devices[i];
        std::cout << "  " << (i + 1) << ". " << device.device_id
            << " (" << device.name << ") - " << device.model;
        if (!device.parent_device_id.empty()) {
            std::cout << " [父设备: " << device.parent_device_id << "]";
        }
        std::cout << std::endl;
    }

    std::cout << "请选择设备 (1-" << all_devices.size() << "): ";
    int choice;
    std::cin >> choice;
    std::cin.ignore();

    if (choice > 0 && choice <= static_cast<int>(all_devices.size())) {
        const auto& selected = all_devices[choice - 1];
        std::cout << "已选择: " << selected.device_id << " (" << selected.name << ")" << std::endl;
        return selected.device_id;
    }

    std::cout << "无效选择" << std::endl;
    return "";
}

auto handle_device_catalog_menu(const sip_server& server) -> void {
    print_separator("设备目录管理");

    std::cout << "目录管理选项:" << std::endl;
    std::cout << "1. 显示完整设备树（包括所有设备）" << std::endl;
    std::cout << "2. 刷新所有设备目录" << std::endl;
    std::cout << "3. 刷新指定设备目录" << std::endl;

    std::cout << "请选择 (1-3): ";
    int catalog_choice;
    std::cin >> catalog_choice;
    std::cin.ignore();

    switch (catalog_choice) {
    case 1: {
        std::cout << "\n完整设备树:" << std::endl;
        display_registered_devices(server);

        // 额外显示所有摄像头列表
        if (const auto cameras = server.get_all_camera_devices(); !cameras.empty()) {
            std::cout << "\n可用摄像头设备汇总 (" << cameras.size() << "个):" << std::endl;
            for (const auto& cam : cameras) {
                std::cout << "  • " << cam.device_id
                    << " (" << cam.name << ") - "
                    << cam.model << " [父设备: "
                    << cam.parent_device_id << "]" << std::endl;
            }
        }
        break;
    }

    case 2: {
        std::cout << "\n正在刷新所有设备目录..." << std::endl;
        for (const auto all_devices = server.get_registered_devices(); const auto& device_id : all_devices) {
            std::cout << "请求设备 " << device_id << " 的目录..." << std::endl;
            if (server.request_catalog(device_id.c_str()) == -1) {
                LOGE("request_catalog error for %s", device_id.c_str());
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        std::cout << "刷新请求已发送，请等待3秒查看结果..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));

        // 显示刷新后的结果
        std::cout << "\n刷新后的设备树:" << std::endl;
        display_registered_devices(server);
        break;
    }

    case 3: {
        const auto devices = server.get_registered_devices();
        if (devices.empty()) {
            std::cout << "无可用设备" << std::endl;
            break;
        }

        std::cout << "选择要刷新目录的设备:" << std::endl;
        for (size_t i = 0; i < devices.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << devices[i] << std::endl;
        }

        std::cout << "请选择设备 (1-" << devices.size() << "): ";
        int device_choice;
        std::cin >> device_choice;
        std::cin.ignore();

        if (device_choice > 0 && device_choice <= static_cast<int>(devices.size())) {
            const auto& device_id = devices[device_choice - 1];
            std::cout << "正在请求设备 " << device_id << " 的目录..." << std::endl;
            if (server.request_catalog(device_id.c_str()) == -1) {
                LOGE("request_catalog error");
            }
            std::cout << "目录请求已发送，请等待3秒查看结果..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(3));

            // 显示该设备的目录
            const auto catalog = server.get_device_catalog(device_id.c_str());
            std::cout << "\n设备 " << device_id << " 的子设备 ("
                << catalog.size() << "个):" << std::endl;
            for (const auto& child : catalog) {
                const char* type_str{};
                switch (child.type) {
                case device_type::camera: type_str = "[摄像头]";
                    break;
                case device_type::nvr: type_str = "[录像机]";
                    break;
                default: type_str = "[其他]";
                    break;
                }
                std::cout << "  • " << child.device_id
                    << " (" << child.name << ") "
                    << type_str << " - "
                    << child.model << " ["
                    << child.status << "]" << std::endl;
            }
        }
        else {
            std::cout << "无效选择" << std::endl;
        }
        break;
    }

    default:
        std::cout << "无效选择" << std::endl;
        break;
    }
}

// 演示PTZ控制功能
auto demo_ptz_control(const sip_server& server) -> void {
    print_separator("PTZ控制演示");

    const std::string device_id = select_camera_device(server);
    if (device_id.empty()) {
        return;
    }

    std::cout << "PTZ控制选项:" << std::endl;
    std::cout << "1. 向上" << std::endl;
    std::cout << "2. 向下" << std::endl;
    std::cout << "3. 向左" << std::endl;
    std::cout << "4. 向右" << std::endl;
    std::cout << "5. 放大" << std::endl;
    std::cout << "6. 缩小" << std::endl;
    std::cout << "7. 停止" << std::endl;
    std::cout << "8. 设置预置位1" << std::endl;
    std::cout << "9. 调用预置位1" << std::endl;
    std::cout << "10. 查询PTZ位置" << std::endl;

    std::cout << "请选择操作 (1-10): ";
    int choice;
    std::cin >> choice;
    std::cin.ignore();

    constexpr int speed = 144; // 默认速度

    switch (choice) {
    case 1:
        if (server.send_ptz_control(device_id.c_str(), ptz_command::ptz_up, speed) == -1) {
            LOGE("send_ptz_control error");
        }
        std::cout << "发送向上命令" << std::endl;
        break;
    case 2:
        if (server.send_ptz_control(device_id.c_str(), ptz_command::ptz_down, speed) == -1) {
            LOGE("send_ptz_control error");
        }
        std::cout << "发送向下命令" << std::endl;
        break;
    case 3:
        if (server.send_ptz_control(device_id.c_str(), ptz_command::ptz_left, speed) == -1) {
            LOGE("send_ptz_control error");
        }
        std::cout << "发送向左命令" << std::endl;
        break;
    case 4:
        if (server.send_ptz_control(device_id.c_str(), ptz_command::ptz_right, speed) == -1) {
            LOGE("send_ptz_control error");
        }
        std::cout << "发送向右命令" << std::endl;
        break;
    case 5:
        if (server.send_ptz_control(device_id.c_str(), ptz_command::ptz_zoom_in, speed) == -1) {
            LOGE("send_ptz_control error");
        }
        std::cout << "发送放大命令" << std::endl;
        break;
    case 6:
        if (server.send_ptz_control(device_id.c_str(), ptz_command::ptz_zoom_out, speed) == -1) {
            LOGE("send_ptz_control error");
        }
        std::cout << "发送缩小命令" << std::endl;
        break;
    case 7:
        if (server.send_ptz_control(device_id.c_str(), ptz_command::ptz_stop, 0) == -1) {
            LOGE("send_ptz_control error");
        }
        std::cout << "发送停止命令" << std::endl;
        break;
    case 8:
        if (server.send_preset_control(device_id.c_str(), preset_operation::set, 1) == -1) {
            LOGE("send_preset_control error");
        }
        std::cout << "设置预置位1" << std::endl;
        break;
    case 9:
        if (server.send_preset_control(device_id.c_str(), preset_operation::call, 1) == -1) {
            LOGE("send_preset_control error");
        }
        std::cout << "调用预置位1" << std::endl;
        break;
    case 10:
        if (server.send_ptz_position_query(device_id.c_str()) == -1) {
            LOGE("send_ptz_position_query error");
        }
        std::cout << "查询PTZ位置" << std::endl;
        break;
    default:
        std::cout << "无效选择" << std::endl;
        break;
    }
}

// 演示录像查询和回放功能
auto demo_recording_operations(sip_server& server) -> void {
    print_separator("录像操作演示");

    std::cout << "录像操作选项:" << std::endl;
    std::cout << "1. 查询录像" << std::endl;
    std::cout << "2. 显示录像列表" << std::endl;
    std::cout << "3. 开始回放" << std::endl;
    std::cout << "4. 显示回放会话" << std::endl;
    std::cout << "5. 停止回放" << std::endl;

    std::cout << "请选择操作 (1-5): ";
    int choice;
    std::cin >> choice;
    std::cin.ignore();

    switch (choice) {
    case 1: {
        const std::string device_id = select_camera_device(server);
        if (device_id.empty()) {
            return;
        }

        std::cout << "请输入开始时间 (格式: YYYY-MM-DDTHH:mm:ss): ";
        std::string start_time;
        std::getline(std::cin, start_time);

        std::cout << "请输入结束时间 (格式: YYYY-MM-DDTHH:mm:ss): ";
        std::string end_time;
        std::getline(std::cin, end_time);

        if (server.request_record_query(device_id.c_str(), start_time.c_str(), end_time.c_str()) == 0) {
            std::cout << "录像查询请求已发送" << std::endl;
            std::cout << "请等待几秒钟后查看录像列表" << std::endl;
        }
        else {
            std::cout << "录像查询请求失败" << std::endl;
        }
        break;
    }
    case 2: {
        const std::string device_id = select_camera_device(server);
        if (device_id.empty()) {
            return;
        }

        if (const auto records = server.get_record_list(device_id.c_str()); records.empty()) {
            std::cout << "无录像记录，请先查询录像" << std::endl;
        }
        else {
            std::cout << "录像记录列表:" << std::endl;
            for (size_t i = 0; i < records.size(); ++i) {
                std::cout << "  " << (i + 1) << ". " << records[i].name
                    << " (" << records[i].start_time << " ~ " << records[i].end_time << ")"
                    << " [" << records[i].file_size << " bytes]" << std::endl;
            }
        }
        break;
    }
    case 3: {
        const std::string device_id = select_camera_device(server);
        if (device_id.empty()) {
            return;
        }

        const auto records = server.get_record_list(device_id.c_str());
        if (records.empty()) {
            std::cout << "无录像记录，请先查询录像" << std::endl;
            break;
        }

        std::cout << "选择要回放的录像:" << std::endl;
        for (size_t i = 0; i < records.size() && i < 10; ++i) {
            std::cout << "  " << (i + 1) << ". " << records[i].name
                << " (" << records[i].start_time << " ~ " << records[i].end_time << ")" << std::endl;
        }

        std::cout << "请选择录像 (1-" << std::min(records.size(), static_cast<size_t>(10)) << "): ";
        int record_choice;
        std::cin >> record_choice;
        std::cin.ignore();

        if (record_choice > 0 && record_choice <= static_cast<int>(std::min(records.size(), static_cast<size_t>(10)))) {
            const auto& record = records[record_choice - 1];
            const std::string session_id = server.start_playback(device_id.c_str(),
                                                                 record.start_time.c_str(), record.end_time.c_str());
            if (!session_id.empty()) {
                std::cout << "回放已开始，会话ID: " << session_id << std::endl;
            }
            else {
                std::cout << "回放启动失败" << std::endl;
            }
        }
        else {
            std::cout << "无效选择" << std::endl;
        }
        break;
    }
    case 4: {
        auto sessions = server.get_playback_sessions();
        if (sessions.empty()) {
            std::cout << "当前无回放会话" << std::endl;
        }
        else {
            std::cout << "当前回放会话:" << std::endl;
            for (size_t i = 0; i < sessions.size(); ++i) {
                std::cout << "  " << (i + 1) << ". " << sessions[i] << std::endl;
            }
        }
        break;
    }
    case 5: {
        auto sessions = server.get_playback_sessions();
        if (sessions.empty()) {
            std::cout << "当前无回放会话" << std::endl;
            break;
        }

        std::cout << "选择要停止的回放会话:" << std::endl;
        for (size_t i = 0; i < sessions.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << sessions[i] << std::endl;
        }

        std::cout << "请选择会话 (1-" << sessions.size() << "): ";
        int session_choice;
        std::cin >> session_choice;
        std::cin.ignore();

        if (session_choice > 0 && session_choice <= static_cast<int>(sessions.size())) {
            const std::string& session_id = sessions[session_choice - 1];
            if (server.stop_playback(session_id.c_str()) == 0) {
                std::cout << "回放已停止" << std::endl;
            }
            else {
                std::cout << "停止回放失败" << std::endl;
            }
        }
        else {
            std::cout << "无效选择" << std::endl;
        }
        break;
    }
    default:
        std::cout << "无效选择" << std::endl;
        break;
    }
}

// 演示文件下载功能
auto demo_file_download(sip_server& server) -> void {
    print_separator("文件下载演示");

    std::cout << "文件下载操作选项:" << std::endl;
    std::cout << "1. 请求文件下载" << std::endl;
    std::cout << "2. 显示下载列表" << std::endl;
    std::cout << "3. 检查下载状态" << std::endl;
    std::cout << "4. 取消下载" << std::endl;

    std::cout << "请选择操作 (1-4): ";
    int choice;
    std::cin >> choice;
    std::cin.ignore();

    switch (choice) {
    case 1: {
        std::string device_id = select_camera_device(server);
        if (device_id.empty()) {
            return;
        }

        std::cout << "请输入开始时间 (格式: YYYY-MM-DDTHH:mm:ss): ";
        std::string start_time;
        std::getline(std::cin, start_time);

        std::cout << "请输入结束时间 (格式: YYYY-MM-DDTHH:mm:ss): ";
        std::string end_time;
        std::getline(std::cin, end_time);

        std::string session_id = server.request_file_download(device_id.c_str(),
                                                              start_time.c_str(), end_time.c_str());
        if (!session_id.empty()) {
            std::cout << "文件下载请求已创建，会话ID: " << session_id << std::endl;
        }
        else {
            std::cout << "文件下载请求失败" << std::endl;
        }
        break;
    }
    case 2: {
        auto downloads = server.list_downloads();
        if (downloads.empty()) {
            std::cout << "当前无下载任务" << std::endl;
        }
        else {
            std::cout << "下载任务列表:" << std::endl;
            for (size_t i = 0; i < downloads.size(); ++i) {
                auto status = server.get_download_status(downloads[i].c_str());
                auto [downloaded, total] = server.get_download_progress(downloads[i].c_str());

                std::cout << "  " << (i + 1) << ". " << downloads[i]
                    << " - 状态: " << static_cast<int>(status);
                if (total > 0) {
                    double progress = static_cast<double>(downloaded) / static_cast<double>(total) * 100.0;
                    std::cout << " - 进度: " << std::fixed << std::setprecision(1) << progress << "%";
                }
                std::cout << std::endl;
            }
        }
        break;
    }
    case 3: {
        auto downloads = server.list_downloads();
        if (downloads.empty()) {
            std::cout << "当前无下载任务" << std::endl;
            break;
        }

        std::cout << "选择要检查的下载任务:" << std::endl;
        for (size_t i = 0; i < downloads.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << downloads[i] << std::endl;
        }

        std::cout << "请选择任务 (1-" << downloads.size() << "): ";
        int download_choice;
        std::cin >> download_choice;
        std::cin.ignore();

        if (download_choice > 0 && download_choice <= static_cast<int>(downloads.size())) {
            const std::string& session_id = downloads[download_choice - 1];
            auto status = server.get_download_status(session_id.c_str());
            auto [downloaded, total] = server.get_download_progress(session_id.c_str());

            std::cout << "下载状态详情:" << std::endl;
            std::cout << "  会话ID: " << session_id << std::endl;
            std::cout << "  状态: " << static_cast<int>(status) << std::endl;
            std::cout << "  已下载: " << downloaded << " bytes" << std::endl;
            std::cout << "  总大小: " << total << " bytes" << std::endl;
            if (total > 0) {
                double progress = static_cast<double>(downloaded) / static_cast<double>(total) * 100.0;
                std::cout << "  进度: " << std::fixed << std::setprecision(2) << progress << "%" << std::endl;
            }
        }
        else {
            std::cout << "无效选择" << std::endl;
        }
        break;
    }
    case 4: {
        auto downloads = server.list_downloads();
        if (downloads.empty()) {
            std::cout << "当前无下载任务" << std::endl;
            break;
        }

        std::cout << "选择要取消的下载任务:" << std::endl;
        for (size_t i = 0; i < downloads.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << downloads[i] << std::endl;
        }

        std::cout << "请选择任务 (1-" << downloads.size() << "): ";
        int download_choice;
        std::cin >> download_choice;
        std::cin.ignore();

        if (download_choice > 0 && download_choice <= static_cast<int>(downloads.size())) {
            const std::string& session_id = downloads[download_choice - 1];
            if (server.cancel_download(session_id.c_str()) == 0) {
                std::cout << "下载已取消" << std::endl;
            }
            else {
                std::cout << "取消下载失败" << std::endl;
            }
        }
        else {
            std::cout << "无效选择" << std::endl;
        }
        break;
    }
    default:
        std::cout << "无效选择" << std::endl;
        break;
    }
}

// 演示抓拍功能
auto demo_snapshot_operations(sip_server& server) -> void {
    print_separator("抓拍功能演示");

    std::cout << "抓拍操作选项:" << std::endl;
    std::cout << "1. 请求抓拍" << std::endl;
    std::cout << "2. 显示抓拍列表" << std::endl;
    std::cout << "3. 检查抓拍状态" << std::endl;

    std::cout << "请选择操作 (1-3): ";
    int choice;
    std::cin >> choice;
    std::cin.ignore();

    switch (choice) {
    case 1: {
        std::string device_id = select_camera_device(server);
        if (device_id.empty()) {
            return;
        }

        std::cout << "请输入图像质量 (1-100, 默认80): ";
        std::string quality_str;
        std::getline(std::cin, quality_str);
        uint32_t quality = quality_str.empty() ? 80 : std::stoul(quality_str);

        std::string session_id = server.request_snapshot(device_id.c_str(), quality);
        if (!session_id.empty()) {
            std::cout << "抓拍请求已创建，会话ID: " << session_id << std::endl;
        }
        else {
            std::cout << "抓拍请求失败" << std::endl;
        }
        break;
    }
    case 2: {
        auto snapshots = server.list_snapshots();
        if (snapshots.empty()) {
            std::cout << "当前无抓拍任务" << std::endl;
        }
        else {
            std::cout << "抓拍任务列表:" << std::endl;
            for (size_t i = 0; i < snapshots.size(); ++i) {
                auto status = server.get_snapshot_status(snapshots[i].c_str());
                std::cout << "  " << (i + 1) << ". " << snapshots[i]
                    << " - 状态: " << static_cast<int>(status) << std::endl;
            }
        }
        break;
    }
    case 3: {
        auto snapshots = server.list_snapshots();
        if (snapshots.empty()) {
            std::cout << "当前无抓拍任务" << std::endl;
            break;
        }

        std::cout << "选择要检查的抓拍任务:" << std::endl;
        for (size_t i = 0; i < snapshots.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << snapshots[i] << std::endl;
        }

        std::cout << "请选择任务 (1-" << snapshots.size() << "): ";
        int snapshot_choice;
        std::cin >> snapshot_choice;
        std::cin.ignore();

        if (snapshot_choice > 0 && snapshot_choice <= static_cast<int>(snapshots.size())) {
            const std::string& session_id = snapshots[snapshot_choice - 1];
            auto status = server.get_snapshot_status(session_id.c_str());

            std::cout << "抓拍状态详情:" << std::endl;
            std::cout << "  会话ID: " << session_id << std::endl;
            std::cout << "  状态: " << static_cast<int>(status);

            switch (status) {
            case snapshot_status::pending:
                std::cout << " (等待中)";
                break;
            case snapshot_status::capturing:
                std::cout << " (抓拍中)";
                break;
            case snapshot_status::completed:
                std::cout << " (完成)";
                break;
            case snapshot_status::failed:
                std::cout << " (失败)";
                break;
            }
            std::cout << std::endl;
        }
        else {
            std::cout << "无效选择" << std::endl;
        }
        break;
    }
    default:
        std::cout << "无效选择" << std::endl;
        break;
    }
}

auto main() -> int {
    // 创建服务器信息
    server_info info(
        "sipserver", // User Agent
        "1234567890123456", // Nonce
        "192.168.124.109", // IP地址
        15060, // SIP端口
        10001, // RTP端口
        "34020000003000000001", // SIP服务器ID
        "3402000000", // SIP域
        "123456789", // SIP密码
        1800, // 会话超时
        3600 // 注册有效期
    );

    // 创建SIP服务器
    sip_server server(&info);

    // 设置存储路径
    server.set_download_root_path("./video_downloads/");
    server.set_snapshot_root_path("./snapshots/");

    print_separator("SIP服务器启动");

    // 启动SIP服务器
    if (server.start() != 0) {
        std::cerr << "SIP服务器启动失败!" << std::endl;
        return -1;
    }

    std::cout << "SIP服务器已启动，等待设备注册..." << std::endl;

    // 初始化设备
    std::cout << "等待设备注册中..." << std::endl;

    int wait_count = 0;
    while (wait_count < 30) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto devices = server.get_registered_devices();
        if (!devices.empty()) {
            std::cout << "\n发现 " << devices.size() << " 个已注册设备!" << std::endl;

            // 显示注册的设备
            for (const auto& device_id : devices) {
                auto info_sub = server.get_device_info(device_id.c_str());
                std::cout << "  • " << device_id << " (" << info_sub.name << ")" << std::endl;
            }

            // 自动请求所有设备的目录
            std::cout << "\n自动获取设备目录..." << std::endl;
            for (const auto& device_id : devices) {
                std::cout << "  请求 " << device_id << " 的目录..." << std::endl;
                if (server.request_catalog(device_id.c_str()) == -1) {
                    LOGE("request_catalog error for %s", device_id.c_str());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            // 等待目录响应
            std::cout << "等待目录响应..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(3));

            // 显示完整的设备树
            std::cout << "\n初始化完成!" << std::endl;
            display_registered_devices(server);

            // 显示摄像头汇总
            auto cameras = server.get_all_camera_devices();
            if (!cameras.empty()) {
                std::cout << "\n发现的摄像头设备:" << std::endl;
                display_all_cameras(server);
            }

            break;
        }

        wait_count++;
        if (wait_count % 5 == 0) {
            std::cout << "仍在等待设备注册... (" << wait_count << "s)" << std::endl;
        }
    }

    if (wait_count >= 30) {
        std::cout << "等待超时，无设备注册。您可以稍后手动刷新设备目录。" << std::endl;
    }

    // 主交互循环
    print_separator("交互式控制菜单");

    while (true) {
        std::cout << "\n请选择操作:" << std::endl;
        std::cout << "1. 显示已注册设备" << std::endl;
        std::cout << "2. 设备目录管理" << std::endl;
        std::cout << "3. PTZ控制" << std::endl;
        std::cout << "4. 录像操作" << std::endl;
        std::cout << "5. 文件下载" << std::endl;
        std::cout << "6. 抓拍功能" << std::endl;
        std::cout << "7. 显示系统状态" << std::endl;
        std::cout << "0. 退出程序" << std::endl;
        std::cout << "请选择 (0-7): ";

        int main_choice;
        std::cin >> main_choice;
        std::cin.ignore(); // 清除输入缓冲区

        switch (main_choice) {
        case 1:
            print_separator("已注册设备");
            display_registered_devices(server);
            break;

        case 2:
            handle_device_catalog_menu(server);
            break;

        case 3:
            demo_ptz_control(server);
            break;

        case 4:
            demo_recording_operations(server);
            break;

        case 5:
            demo_file_download(server);
            break;

        case 6:
            demo_snapshot_operations(server);
            break;

        case 7: {
            print_separator("系统状态");
            auto devices_sub = server.get_registered_devices();
            auto cameras = server.get_all_camera_devices();
            auto downloads = server.list_downloads();
            auto snapshots = server.list_snapshots();
            auto playbacks = server.get_playback_sessions();

            std::cout << "服务器状态: " << (server.is_running() ? "运行中" : "已停止") << std::endl;
            std::cout << "已注册设备数: " << devices_sub.size() << std::endl;
            std::cout << "摄像头设备数: " << cameras.size() << std::endl;
            std::cout << "下载任务数: " << downloads.size() << std::endl;
            std::cout << "抓拍任务数: " << snapshots.size() << std::endl;
            std::cout << "回放会话数: " << playbacks.size() << std::endl;

            if (!cameras.empty()) {
                std::cout << "\n摄像头设备详情:" << std::endl;
                for (size_t i = 0; i < cameras.size() && i < 5; ++i) {
                    const auto& cam = cameras[i];
                    std::cout << "  " << cam.device_id << " (" << cam.name
                        << ") - 父设备: " << cam.parent_device_id << std::endl;
                }
                if (cameras.size() > 5) {
                    std::cout << "  ... 还有 " << (cameras.size() - 5) << " 个摄像头" << std::endl;
                }
            }
            break;
        }

        case 0:
            std::cout << "正在关闭服务器..." << std::endl;
            server.stop();
            std::cout << "程序已退出" << std::endl;
            return 0;

        default:
            std::cout << "无效选择，请重试" << std::endl;
            break;
        }

        wait_for_user_input("\n操作完成");
    }
}
