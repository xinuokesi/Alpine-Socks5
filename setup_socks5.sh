#!/bin/sh
# Alpine Socks5代理一键安装脚本 - 支持保活和开机自启
# 支持通过GitHub一键安装: curl -fsSL https://raw.githubusercontent.com/你的用户名/你的仓库名/main/setup_socks5.sh | sh

# 检查是否为root用户
if [ "$(id -u)" -ne 0 ]; then
   echo "此脚本需要root权限，请使用sudo或以root身份运行"
   exit 1
fi

# 检查系统是否为Alpine
if [ ! -f /etc/alpine-release ]; then
    echo "此脚本仅适用于Alpine Linux系统"
    exit 1
fi

# 设置变量
CONFIG_FILE="/etc/3proxy/3proxy.cfg"
SERVICE_NAME="3proxy"
CONFIG_INFO="/etc/3proxy/proxy_info.txt"
KEEPALIVE_SCRIPT="/etc/periodic/15min/3proxy_keepalive"
PROXY_BIN=""  # 将由脚本自动检测
PUBLIC_IP=""  # 公网IP地址

# 检测是否通过管道执行
is_pipe_execution() {
    # 检查标准输入是否为终端
    if [ ! -t 0 ]; then
        return 0  # 是管道执行
    else
        return 1  # 不是管道执行
    fi
}

# 检查文件是否为真正的3proxy可执行文件（不是服务脚本）
is_real_3proxy_binary() {
    file_path="$1"
    
    # 检查文件是否存在且可执行
    if [ ! -f "$file_path" ] || [ ! -x "$file_path" ]; then
        return 1
    fi
    
    # 排除服务脚本路径
    if echo "$file_path" | grep -q "/etc/init.d"; then
        return 1
    fi
    
    # 检查文件类型
    file_type=$(file -b "$file_path" 2>/dev/null)
    
    # 检查是否为脚本文件（服务脚本通常是shell脚本）
    if echo "$file_type" | grep -q "shell script"; then
        return 1
    fi
    
    # 检查是否为ELF二进制文件
    if echo "$file_type" | grep -q "ELF" || echo "$file_type" | grep -q "executable"; then
        return 0
    fi
    
    # 最后再尝试运行测试
    if "$file_path" -h 2>&1 | grep -q "3proxy version"; then
        return 0
    fi
    
    # 默认假设不是真正的3proxy
    return 1
}

# 查找3proxy可执行文件的路径
find_3proxy_path() {
    echo "正在检测3proxy安装路径..."
    
    # 先尝试在常见位置搜索
    for path in "/usr/bin/3proxy" "/usr/sbin/3proxy" "/usr/local/bin/3proxy" "/usr/local/sbin/3proxy" "/bin/3proxy" "/sbin/3proxy"; do
        if [ -x "$path" ] && is_real_3proxy_binary "$path"; then
            PROXY_BIN="$path"
            echo "找到3proxy可执行文件: $PROXY_BIN"
            return 0
        fi
    done
    
    # 使用which命令查找
    possible_path=$(which 3proxy 2>/dev/null)
    if [ -n "$possible_path" ] && is_real_3proxy_binary "$possible_path"; then
        PROXY_BIN="$possible_path"
        echo "找到3proxy可执行文件: $PROXY_BIN"
        return 0
    fi
    
    # 如果仍然找不到，使用find命令搜索整个系统
    echo "在常见位置未找到3proxy，正在全盘搜索..."
    for found_path in $(find / -name "3proxy" -type f -executable 2>/dev/null); do
        if is_real_3proxy_binary "$found_path"; then
            PROXY_BIN="$found_path"
            echo "找到3proxy可执行文件: $PROXY_BIN"
            return 0
        fi
    done
    
    # 特殊场景：直接尝试使用apk获取文件列表
    echo "尝试从安装包获取3proxy路径..."
    for pkg_file in $(apk info -L 3proxy 2>/dev/null | grep -v "/etc/init.d" | grep "bin/3proxy$"); do
        if [ -x "$pkg_file" ] && is_real_3proxy_binary "$pkg_file"; then
            PROXY_BIN="$pkg_file"
            echo "从安装包找到3proxy: $PROXY_BIN"
            return 0
        fi
    done
    
    echo "未找到可执行的3proxy，将尝试安装"
    return 1
}

# 安装必要的软件 - 确保在其他功能之前调用
install_required_software() {
    echo "正在安装必要的软件..."
    apk update
    
    # 首先安装基本工具
    apk add curl net-tools openssl lsof file
    
    # 安装3proxy并验证
    echo "正在安装3proxy..."
    apk add 3proxy
    
    if ! find_3proxy_path; then
        echo "3proxy安装失败，尝试从其他软件源安装..."
        # 尝试添加社区仓库
        echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories
        apk update
        apk add 3proxy
        
        if ! find_3proxy_path; then
            echo "尝试编译安装3proxy..."
            # 尝试从源码编译
            apk add gcc make musl-dev
            mkdir -p /tmp/3proxy_build
            cd /tmp/3proxy_build
            curl -L -o 3proxy.tar.gz https://github.com/z3APA3A/3proxy/archive/0.9.4.tar.gz
            tar xzf 3proxy.tar.gz
            cd 3proxy-*
            make -f Makefile.Linux
            make -f Makefile.Linux install
            cd /
            rm -rf /tmp/3proxy_build
            
            # 再次检查安装
            find_3proxy_path
        fi
    fi
    
    # 如果还是找不到3proxy，退出
    if [ -z "$PROXY_BIN" ]; then
        echo "错误: 无法安装3proxy，请手动安装后再运行此脚本"
        exit 1
    fi
    
    # 确保二进制文件正确
    echo "最终确认3proxy二进制文件..."
    if [ -n "$PROXY_BIN" ]; then
        echo "3proxy二进制文件路径: $PROXY_BIN"
        echo "文件类型: $(file -b "$PROXY_BIN")"
        echo "尝试获取版本信息: "
        $PROXY_BIN -v 2>&1 || echo "无法获取版本信息"
    fi
    
    # 创建配置目录
    mkdir -p /etc/3proxy
    mkdir -p /etc/periodic/15min
    mkdir -p /var/log
    touch /var/log/3proxy.log
    chmod 644 /var/log/3proxy.log
}

# 获取公网IP地址
get_public_ip() {
    echo "正在获取公网IP地址..."
    # 尝试多种服务来获取公网IP
    PUBLIC_IP=$(curl -s -4 https://api.ipify.org 2>/dev/null || 
                curl -s -4 https://ifconfig.me 2>/dev/null || 
                curl -s -4 https://ip.3322.net 2>/dev/null || 
                curl -s -4 https://ipinfo.io/ip 2>/dev/null ||
                curl -s -4 https://ipecho.net/plain 2>/dev/null)
    
    # 如果无法获取公网IP，使用本地IP
    if [ -z "$PUBLIC_IP" ]; then
        echo "无法获取公网IP，将使用本地IP"
        PUBLIC_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
    fi
    
    echo "检测到IP地址: $PUBLIC_IP"
}

# 设置保活功能
setup_keepalive() {
    echo "设置保活功能..."
    
    # 确保我们有正确的3proxy路径
    if [ -z "$PROXY_BIN" ]; then
        find_3proxy_path
    fi
    
    # 创建保活脚本
    cat > "$KEEPALIVE_SCRIPT" << EOF
#!/bin/sh
# 3proxy保活脚本

# 检查3proxy是否运行
if ! pgrep -f 3proxy >/dev/null 2>&1; then
    logger -t "3proxy_keepalive" "检测到3proxy进程未运行，正在重启..."
    
    # 检查是否有配置文件
    if [ -f /etc/3proxy/3proxy.cfg ]; then
        # 先尝试通过服务重启
        rc-service 3proxy restart
        
        # 检查是否重启成功
        if ! pgrep -f 3proxy >/dev/null 2>&1; then
            # 服务方式失败，尝试直接运行
            logger -t "3proxy_keepalive" "服务重启失败，尝试手动启动"
            PROXY_PATH="$PROXY_BIN"
            if [ -x "\$PROXY_PATH" ]; then
                cd /etc/3proxy && \$PROXY_PATH
            else
                # 尝试再次查找路径
                PROXY_PATH=\$(which 3proxy 2>/dev/null)
                if [ -n "\$PROXY_PATH" ] && [ -x "\$PROXY_PATH" ] && ! echo "\$PROXY_PATH" | grep -q "init.d"; then
                    cd /etc/3proxy && \$PROXY_PATH
                fi
            fi
        fi
        
        logger -t "3proxy_keepalive" "3proxy服务已尝试重启"
    else
        logger -t "3proxy_keepalive" "配置文件不存在，无法重启服务"
    fi
fi

# 检查端口是否开放
PORT=\$(grep "^socks" /etc/3proxy/3proxy.cfg | grep -oE "[0-9]+" | head -n 1)
if [ -n "\$PORT" ]; then
    if ! (netstat -tln | grep ":\$PORT " >/dev/null 2>&1 || lsof -i :\$PORT >/dev/null 2>&1); then
        logger -t "3proxy_keepalive" "检测到端口 \$PORT 未开放，正在重启3proxy..."
        rc-service 3proxy restart
        logger -t "3proxy_keepalive" "3proxy服务已重启"
    fi
fi
EOF

    # 设置权限
    chmod +x "$KEEPALIVE_SCRIPT"
    
    # 创建定时任务（如果没有安装cron，则安装）
    if ! command -v crond >/dev/null 2>&1; then
        apk add dcron
        rc-update add dcron default
        rc-service dcron start
    fi
    
    # 确保crond服务运行
    if ! pgrep crond >/dev/null 2>&1; then
        rc-service dcron start
    fi
    
    echo "保活功能设置完成，每15分钟将检查一次代理服务状态。"
}

# 生成随机字符串 - 提供备选方案
generate_random_string() {
    length=$1
    
    # 首先尝试使用openssl生成随机字符串
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c "$length"
    else
        # 如果openssl不可用，使用/dev/urandom作为备用
        if [ -c /dev/urandom ]; then
            cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$length"
        else
            # 最后的备用方法，使用$RANDOM
            local result=""
            local chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            local char_count=${#chars}
            for i in $(seq 1 "$length"); do
                local idx=$((RANDOM % char_count))
                result="${result}${chars:idx:1}"
            done
            echo "$result"
        fi
    fi
}

# 生成随机端口 (1024-65535)
generate_random_port() {
    echo $((RANDOM % 64511 + 1024))
}

# 创建服务启动脚本
create_service_script() {
    echo "配置服务启动脚本..."
    
    # 确保我们知道3proxy的路径
    if [ -z "$PROXY_BIN" ]; then
        find_3proxy_path
    fi
    
    if [ -z "$PROXY_BIN" ]; then
        echo "错误: 无法找到3proxy可执行文件路径，无法创建服务脚本"
        exit 1
    fi
    
    # 创建OpenRC服务文件
    cat > /etc/init.d/3proxy << EOF
#!/sbin/openrc-run

name="3proxy"
description="Tiny free proxy server"
command="$PROXY_BIN"
pidfile="/run/\${RC_SVCNAME}.pid"
command_background="yes"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting \$name"
    cd /etc/3proxy && \$command
    eend \$?
}

start_pre() {
    checkpath --directory --owner root:root --mode 0755 /var/log
}
EOF
    chmod +x /etc/init.d/3proxy
    
    # 添加到默认运行级别
    rc-update add 3proxy default 2>/dev/null
    
    echo "服务脚本已创建: /etc/init.d/3proxy"
}

# 创建代理配置
create_proxy_config() {
    local port=$1
    local username=$2
    local password=$3
    
    # 确保配置目录存在
    mkdir -p /etc/3proxy
    
    # 创建配置文件 - 注意格式符合3proxy要求
    cat > "$CONFIG_FILE" << EOF
#!/usr/bin/env 3proxy
daemon
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
log /var/log/3proxy.log D
logformat "- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"
auth strong
users $username:CL:$password
allow $username
socks -p$port
EOF

    # 保存代理信息
    cat > "$CONFIG_INFO" << EOF
代理信息:
==================
协议: socks5
端口: $port
用户名: $username
密码: $password
==================
EOF

    chmod 600 "$CONFIG_INFO"
    
    # 设置权限
    chmod 755 "$CONFIG_FILE"
    
    echo "代理配置文件已创建: $CONFIG_FILE"
}

# 创建备用独立配置
create_standalone_config() {
    local port=$1
    local username=$2
    local password=$3
    
    # 创建一个更简单的配置文件，用于直接启动
    cat > "/etc/3proxy/3proxy.standalone.cfg" << EOF
auth strong
users $username:CL:$password
allow $username
log /var/log/3proxy.log
logformat "L%d-%m-%Y %H:%M:%S %z %N.%p %E %U %C:%c %R:%r %O %I %h %T"
socks -p$port
EOF

    chmod 755 "/etc/3proxy/3proxy.standalone.cfg"
    echo "已创建备用独立配置文件: /etc/3proxy/3proxy.standalone.cfg"
}

# 配置随机代理
configure_random_proxy() {
    echo "配置随机代理..."
    
    port=$(generate_random_port)
    username=$(generate_random_string 8)
    password=$(generate_random_string 12)
    
    create_proxy_config "$port" "$username" "$password"
    create_standalone_config "$port" "$username" "$password"
    restart_proxy
    
    echo "随机代理已配置完成!"
    view_proxy_info
}

# 配置自定义代理
configure_custom_proxy() {
    echo "配置自定义代理..."
    
    # 如果是管道执行，使用默认值
    if is_pipe_execution; then
        port=$(generate_random_port)
        username=$(generate_random_string 8)
        password=$(generate_random_string 12)
    else
        echo -n "请输入端口号 (1024-65535): "
        read -r port
        
        # 验证端口
        if ! [ "$port" -eq "$port" ] 2>/dev/null || [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
            echo "无效的端口号，使用随机端口。"
            port=$(generate_random_port)
        fi
        
        echo -n "请输入用户名 (留空则随机生成): "
        read -r username
        if [ -z "$username" ]; then
            username=$(generate_random_string 8)
        fi
        
        echo -n "请输入密码 (留空则随机生成): "
        read -r password
        if [ -z "$password" ]; then
            password=$(generate_random_string 12)
        fi
    fi
    
    create_proxy_config "$port" "$username" "$password"
    create_standalone_config "$port" "$username" "$password"
    restart_proxy
    
    echo "自定义代理已配置完成!"
    view_proxy_info
}

# 检查日志文件错误
check_log_for_errors() {
    echo "检查服务日志中的错误..."
    if [ -f /var/log/3proxy.log ]; then
        tail -n 20 /var/log/3proxy.log
    else
        echo "日志文件不存在"
    fi
    
    # 尝试获取3proxy配置示例或用法
    if [ -n "$PROXY_BIN" ] && ! echo "$PROXY_BIN" | grep -q "init.d"; then
        echo "查看3proxy帮助信息:"
        $PROXY_BIN -h 2>&1 || $PROXY_BIN --help 2>&1 || $PROXY_BIN 2>&1
        
        echo "检查配置文件内容:"
        cat "$CONFIG_FILE"
    else
        echo "警告: 未找到有效的3proxy二进制程序，无法获取帮助信息"
        # 尝试重新查找
        find_3proxy_path
    fi
}

# 直接启动3proxy（不使用服务）
start_proxy_directly() {
    if [ -z "$PROXY_BIN" ] || echo "$PROXY_BIN" | grep -q "init.d"; then
        echo "重新查找3proxy二进制文件..."
        find_3proxy_path
    fi
    
    if [ -n "$PROXY_BIN" ] && [ -f "$CONFIG_FILE" ]; then
        echo "尝试直接启动3proxy..."
        echo "使用二进制文件: $PROXY_BIN"
        
        # 停止任何现有的3proxy进程
        pkill -f 3proxy 2>/dev/null
        
        # 根据目录直接运行3proxy（不使用配置文件路径参数）
        cd /etc/3proxy/
        $PROXY_BIN &
        
        sleep 2
        
        # 检查是否成功启动
        if pgrep -f 3proxy >/dev/null; then
            echo "3proxy已成功直接启动!"
            return 0
        else
            echo "直接启动失败! 尝试其他启动方式..."
            
            # 尝试不同的启动方式
            echo "尝试方法2: 使用备用配置文件"
            cd /etc/3proxy/
            $PROXY_BIN 3proxy.standalone.cfg &
            sleep 1
            
            if pgrep -f 3proxy >/dev/null; then
                echo "3proxy已成功以方法2启动!"
                return 0
            else
                echo "所有方法都失败了!"
                return 1
            fi
        fi
    else
        echo "无法直接启动3proxy: 可执行文件或配置文件不存在"
        return 1
    fi
}

# 重启代理服务
restart_proxy() {
    echo "重启代理服务..."
    
    # 确保服务脚本存在
    if [ ! -f /etc/init.d/3proxy ]; then
        create_service_script
    fi
    
    # 获取当前配置
    PORT=$(grep "socks -p" "$CONFIG_FILE" 2>/dev/null | sed -E 's/socks -p([0-9]+)/\1/')
    USERNAME=$(grep "users" "$CONFIG_FILE" 2>/dev/null | cut -d: -f1 | awk '{print $2}')
    PASSWORD=$(grep "users" "$CONFIG_FILE" 2>/dev/null | cut -d: -f3 | awk '{print $1}')
    
    # 如果配置不完整，尝试从INFO文件获取
    if [ -z "$PORT" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
        if [ -f "$CONFIG_INFO" ]; then
            echo "从备份信息恢复配置..."
            PORT=$(grep "端口:" "$CONFIG_INFO" | awk '{print $2}')
            USERNAME=$(grep "用户名:" "$CONFIG_INFO" | awk '{print $2}')
            PASSWORD=$(grep "密码:" "$CONFIG_INFO" | awk '{print $2}')
        fi
    fi
    
    # 如果仍然不完整，使用默认值
    if [ -z "$PORT" ]; then
        PORT=$(generate_random_port)
    fi
    if [ -z "$USERNAME" ]; then
        USERNAME=$(generate_random_string 8)
    fi
    if [ -z "$PASSWORD" ]; then
        PASSWORD=$(generate_random_string 12)
    fi
    
    # 先尝试停止所有3proxy进程
    pkill -f 3proxy 2>/dev/null
    sleep 1
    
    # 确保我们有正确的二进制文件
    if [ -z "$PROXY_BIN" ] || echo "$PROXY_BIN" | grep -q "init.d"; then
        echo "重新查找3proxy二进制文件..."
        find_3proxy_path
    fi
    
    # 尝试启动服务
    echo "尝试通过服务启动3proxy..."
    if rc-service "$SERVICE_NAME" start; then
        echo "代理服务已通过服务管理器成功启动!"
    else
        echo "服务启动失败，尝试直接启动..."
        
        # 尝试直接启动
        if start_proxy_directly; then
            echo "成功通过直接启动方式运行3proxy!"
        else
            echo "所有启动方法都失败，尝试诊断问题..."
            echo "1. 检查3proxy二进制文件是否存在并可执行:"
            find_3proxy_path
            ls -la "$PROXY_BIN"
            
            echo "2. 测试3proxy是否可以直接运行:"
            $PROXY_BIN -v 2>&1 || echo "无法运行3proxy二进制文件"
            
            echo "3. 检查配置文件:"
            cat "$CONFIG_FILE"
            
            echo "错误: 无法启动3proxy服务，请检查配置和日志"
        fi
    fi
    
    # 检查3proxy进程
    if pgrep -f 3proxy >/dev/null; then
        echo "确认3proxy进程正在运行:"
        ps aux | grep 3proxy | grep -v grep
    else
        echo "警告: 未检测到3proxy进程运行"
    fi
    
    # 检查端口是否开放
    if [ -n "$PORT" ]; then
        echo "检查端口 $PORT 是否开放..."
        
        # 使用多种方法检查端口
        if netstat -tln | grep ":$PORT " >/dev/null; then
            echo "使用netstat确认端口 $PORT 已开放"
        elif command -v lsof >/dev/null && lsof -i ":$PORT" >/dev/null; then
            echo "使用lsof确认端口 $PORT 已开放"
        elif nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
            echo "使用nc确认端口 $PORT 已开放"
        else
            echo "警告: 端口 $PORT 似乎未开放，可能需要检查配置或防火墙"
        fi
    fi
}

# 查看代理信息
view_proxy_info() {
    if [ -f "$CONFIG_INFO" ]; then
        echo "=== 当前代理配置 ==="
        cat "$CONFIG_INFO"
        
        # 获取并显示服务器IP
        echo ""
        echo "服务器IP地址:"
        
        # 显示本地IP
        echo "本地IP:"
        ip addr | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1
        
        # 获取并显示公网IP
        if [ -z "$PUBLIC_IP" ]; then
            get_public_ip
        fi
        
        if [ -n "$PUBLIC_IP" ]; then
            echo "公网IP: $PUBLIC_IP"
        fi
        
        echo "===================="
        
        # 显示服务状态
        echo "服务状态:"
        rc-service "$SERVICE_NAME" status || echo "服务未通过服务管理器运行"
        
        # 检查3proxy进程
        echo "3proxy进程状态:"
        ps aux | grep 3proxy | grep -v grep || echo "未找到3proxy进程"
        
        # 检查端口是否开放
        PORT=$(grep "socks -p" "$CONFIG_FILE" | sed -E 's/socks -p([0-9]+)/\1/')
        if [ -n "$PORT" ]; then
            echo "端口状态 ($PORT):"
            (netstat -tln | grep ":$PORT " || lsof -i ":$PORT" 2>/dev/null) || echo "端口 $PORT 未检测到开放"
        fi
        echo "===================="
    else
        echo "未找到代理配置信息。"
    fi
}

# 检查防火墙并添加端口规则
configure_firewall() {
    PORT=$(grep "socks -p" "$CONFIG_FILE" | sed -E 's/socks -p([0-9]+)/\1/')
    if [ -n "$PORT" ]; then
        echo "配置防火墙规则..."
        
        # 检查是否安装了iptables
        if command -v iptables >/dev/null 2>&1; then
            iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || \
                iptables -A INPUT -p tcp --dport "$PORT" -j ACCEPT
            echo "已添加iptables规则允许端口 $PORT"
            
            # 保存iptables规则（如果有iptables-save）
            if command -v iptables-save >/dev/null 2>&1; then
                if [ -d /etc/iptables ]; then
                    iptables-save > /etc/iptables/rules.v4
                    echo "已保存iptables规则"
                fi
            fi
        fi
        
        # 如果使用ufw
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
            ufw allow "$PORT"/tcp
            echo "已添加ufw规则允许端口 $PORT"
        fi
    fi
}

# 尝试多种方式启动3proxy
try_all_startup_methods() {
    echo "尝试所有可能的3proxy启动方法..."
    
    # 首先确保我们有正确的3proxy二进制文件
    if [ -z "$PROXY_BIN" ] || echo "$PROXY_BIN" | grep -q "init.d"; then
        PROXY_BIN=""
        echo "重新查找3proxy二进制文件..."
        
        # 手动搜索可能的位置
        for binary in "/usr/bin/3proxy" "/usr/sbin/3proxy" "/usr/local/bin/3proxy" "/usr/local/sbin/3proxy"; do
            if [ -x "$binary" ] && ! echo "$binary" | grep -q "init.d"; then
                file_type=$(file -b "$binary" 2>/dev/null)
                if echo "$file_type" | grep -q "ELF" || echo "$file_type" | grep -q "executable"; then
                    PROXY_BIN="$binary"
                    echo "找到二进制文件: $PROXY_BIN"
                    break
                fi
            fi
        done
        
        # 如果还是找不到，尝试从包管理器获取
        if [ -z "$PROXY_BIN" ]; then
            echo "尝试从安装包获取3proxy位置..."
            pkg_file=$(apk info -L 3proxy 2>/dev/null | grep "bin/3proxy$" | head -n 1)
            if [ -n "$pkg_file" ] && [ -x "$pkg_file" ] && ! echo "$pkg_file" | grep -q "init.d"; then
                PROXY_BIN="$pkg_file"
                echo "从包找到3proxy: $PROXY_BIN"
            fi
        fi
        
        # 如果仍然没有找到，尝试手动安装3proxy
        if [ -z "$PROXY_BIN" ]; then
            echo "尝试安装/重新安装3proxy..."
            apk del 3proxy
            apk add 3proxy
            
            # 再次查找
            for binary in "/usr/bin/3proxy" "/usr/sbin/3proxy"; do
                if [ -x "$binary" ] && ! echo "$binary" | grep -q "init.d"; then
                    PROXY_BIN="$binary"
                    echo "重新安装后找到: $PROXY_BIN"
                    break
                fi
            done
        fi
    fi
    
    # 如果仍然没有找到，退出
    if [ -z "$PROXY_BIN" ]; then
        echo "错误: 无法找到有效的3proxy二进制文件，请手动安装并确保正确配置PATH"
        return 1
    fi
    
    # 获取当前配置或使用默认配置
    local port=$(grep "端口:" "$CONFIG_INFO" 2>/dev/null | awk '{print $2}')
    local username=$(grep "用户名:" "$CONFIG_INFO" 2>/dev/null | awk '{print $2}')
    local password=$(grep "密码:" "$CONFIG_INFO" 2>/dev/null | awk '{print $2}')
    
    # 如果仍然为空，使用随机值
    if [ -z "$port" ]; then port=$(generate_random_port); fi
    if [ -z "$username" ]; then username=$(generate_random_string 8); fi
    if [ -z "$password" ]; then password=$(generate_random_string 12); fi
    
    # 停止任何现有的3proxy进程
    pkill -f 3proxy 2>/dev/null
    sleep 1
    
    echo "准备使用以下参数尝试启动3proxy:"
    echo "二进制文件: $PROXY_BIN"
    echo "端口: $port, 用户名: $username, 密码: ******"
    
    # 方法1: 使用临时配置文件直接运行3proxy
    echo "尝试方法1: 使用临时配置文件"
    local tmp_config="/tmp/3proxy.tmp.cfg"
    cat > "$tmp_config" << EOF
#!/usr/bin/3proxy
auth strong
users $username:CL:$password
allow $username
socks -p$port
EOF
    
    chmod 755 "$tmp_config"
    cd /tmp
    $PROXY_BIN "$tmp_config" &
    sleep 2
    
    if pgrep -f 3proxy >/dev/null; then
        echo "方法1成功!"
        # 保存成功的配置
        cp "$tmp_config" "$CONFIG_FILE"
        return 0
    fi
    
    # 方法2: 最简单的配置
    echo "尝试方法2: 最简单的配置"
    local simple_config="/tmp/3proxy.simple.cfg"
    echo "socks -p$port" > "$simple_config"
    cd /tmp
    $PROXY_BIN "$simple_config" &
    sleep 2
    
    if pgrep -f 3proxy >/dev/null; then
        echo "方法2成功!"
        # 更新配置信息
        echo "注意: 使用了简单配置，没有用户验证"
        return 0
    fi
    
    # 方法3: 不带参数直接运行
    echo "尝试方法3: 不带参数直接运行"
    cd /etc/3proxy
    $PROXY_BIN &
    sleep 2
    
    if pgrep -f 3proxy >/dev/null; then
        echo "方法3成功!"
        return 0
    fi
    
    # 方法4: 测试是否是其他命令格式
    echo "尝试方法4: 使用命令行格式"
    cd /tmp
    $PROXY_BIN "socks" "-p$port" &
    sleep 2
    
    if pgrep -f 3proxy >/dev/null; then
        echo "方法4成功!"
        return 0
    fi
    
    echo "所有启动方法均失败!"
    echo "3proxy帮助信息:"
    $PROXY_BIN -h 2>&1 || $PROXY_BIN --help 2>&1 || $PROXY_BIN 2>&1
    return 1
}

# 手动安装3proxy
manual_install_3proxy() {
    echo "尝试手动安装3proxy..."
    
    # 停止现有服务
    rc-service 3proxy stop 2>/dev/null
    pkill -f 3proxy 2>/dev/null
    
    # 卸载现有包
    apk del 3proxy
    
    # 安装编译工具
    apk add gcc make musl-dev wget
    
    # 创建临时目录
    mkdir -p /tmp/3proxy_install
    cd /tmp/3proxy_install
    
    # 下载3proxy
    wget https://<think>这个错误信息非常明确，表明脚本找到的所谓"3proxy"二进制文件实际上是 `/etc/init.d/3proxy` 服务控制脚本，而不是真正的3proxy可执行文件。

问题分析：
1. `/etc/init.d/3proxy` 是OpenRC的服务启动脚本，不是3proxy程序本身
2. 错误 "unknown function" 和显示的帮助输出都是OpenRC服务脚本的特征
3. `find_3proxy_path` 函数没有正确识别出真正的3proxy可执行文件

需要修复的问题：
1. 改进 `is_real_3proxy_binary` 函数，更准确地区分服务脚本和真正的3proxy二进制文件
2. 添加更严格的检测机制，确保找到的是真正的3proxy二进制文件
3. 如果无法找到真正的3proxy，提供明确的报错信息</think>

问题在于脚本找到的 "3proxy" 可执行文件实际上是服务控制脚本 (`/etc/init.d/3proxy`)，而不是真正的3proxy二进制程序。

这里有一个修复后的脚本片段，专注于改进3proxy二进制文件的检测部分：

```bash
# 检查文件是否为真正的3proxy可执行文件（不是服务脚本）
is_real_3proxy_binary() {
    file_path="$1"
    
    # 检查文件是否存在且可执行
    if [ ! -f "$file_path" ] || [ ! -x "$file_path" ]; then
        return 1
    fi
    
    # 排除init.d脚本
    if echo "$file_path" | grep -q "/etc/init.d"; then
        return 1
    fi
    
    # 检查文件类型
    file_type=$(file -b "$file_path" 2>/dev/null)
    
    # 如果是shell脚本，直接排除
    if echo "$file_type" | grep -q "shell script"; then
        return 1
    fi
    
    # 检查是否为ELF二进制文件
    if echo "$file_type" | grep -q "ELF" || echo "$file_type" | grep -q "executable"; then
        # 尝试执行带-v参数，验证是否真正的3proxy
        if "$file_path" -v 2>&1 | grep -q "3proxy version"; then
            return 0
        fi
        
        # 如果-v不能用，尝试无参数运行，看输出是否包含3proxy相关信息
        if "$file_path" 2>&1 | grep -q -i "3proxy"; then
            # 排除服务脚本输出
            if ! "$file_path" 2>&1 | grep -q "Usage: 3proxy 
$$
options
$$
 stop"; then
                return 0
            fi
        fi
    fi
    
    # 默认假设不是真正的3proxy
    return 1
}

# 修改查找3proxy路径函数
find_3proxy_path() {
    echo "正在检测3proxy安装路径..."
    PROXY_BIN=""  # 重置变量
    
    # 使用which查找
    which_path=$(which 3proxy 2>/dev/null)
    if [ -n "$which_path" ] && is_real_3proxy_binary "$which_path"; then
        PROXY_BIN="$which_path"
        echo "找到3proxy可执行文件: $PROXY_BIN"
        return 0
    fi
    
    # 在常见位置查找
    for path in "/usr/bin/3proxy" "/usr/sbin/3proxy" "/usr/local/bin/3proxy" "/usr/local/sbin/3proxy"; do
        if [ -x "$path" ] && is_real_3proxy_binary "$path"; then
            PROXY_BIN="$path"
            echo "找到3proxy可执行文件: $PROXY_BIN"
            return 0
        fi
    done
    
    # 如果找不到，重新安装3proxy
    echo "未找到真正的3proxy二进制文件，尝试重新安装..."
    apk del 3proxy 2>/dev/null
    apk add 3proxy
    
    # 再次检查安装
    for path in "/usr/bin/3proxy" "/usr/sbin/3proxy"; do
        if [ -x "$path" ] && is_real_3proxy_binary "$path"; then
            PROXY_BIN="$path"
            echo "重新安装后找到3proxy: $PROXY_BIN"
            return 0
        fi
    done
    
    echo "错误: 无法找到有效的3proxy二进制文件。"
    return 1
}
