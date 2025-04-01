#!/bin/sh
# Alpine Socks5代理一键安装脚本 - 支持保活和开机自启
# 支持通过GitHub一键安装: curl -fsSL https://raw.githubusercontent.com/xinuokesi/Alpine-Socks5/main/setup_socks5.sh | sh

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

# 检测是否通过管道执行
is_pipe_execution() {
    # 检查标准输入是否为终端
    if [ ! -t 0 ]; then
        return 0  # 是管道执行
    else
        return 1  # 不是管道执行
    fi
}

# 安装必要的软件
install_required_software() {
    echo "正在安装必要的软件..."
    apk update
    apk add 3proxy openssl curl
    
    # 创建配置目录
    mkdir -p /etc/3proxy
    mkdir -p /etc/periodic/15min
    
    # 确保3proxy服务设置
    rc-update add 3proxy default 2>/dev/null
}

# 设置保活功能
setup_keepalive() {
    echo "设置保活功能..."
    
    # 创建保活脚本
    cat > "$KEEPALIVE_SCRIPT" << 'EOF'
#!/bin/sh
# 3proxy保活脚本

# 检查3proxy是否运行
if ! rc-service 3proxy status >/dev/null 2>&1; then
    logger -t "3proxy_keepalive" "检测到3proxy服务未运行，正在重启..."
    rc-service 3proxy restart
    logger -t "3proxy_keepalive" "3proxy服务已重启"
fi

# 检查端口是否开放
PORT=$(grep "socks -p" /etc/3proxy/3proxy.cfg | sed -E 's/socks -p([0-9]+)/\1/')
if [ -n "$PORT" ]; then
    if ! netstat -tulpn | grep ":$PORT" | grep "3proxy" >/dev/null 2>&1; then
        logger -t "3proxy_keepalive" "检测到端口 $PORT 未开放，正在重启3proxy..."
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
    if ! rc-service dcron status >/dev/null 2>&1; then
        rc-service dcron start
    fi
    
    echo "保活功能设置完成，每15分钟将检查一次代理服务状态。"
}

# 生成随机字符串
generate_random_string() {
    length=$1
    openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c "$length"
}

# 生成随机端口 (1024-65535)
generate_random_port() {
    echo $((RANDOM % 64511 + 1024))
}

# 创建服务启动脚本
create_service_script() {
    echo "配置服务启动脚本..."
    
    # 创建OpenRC服务文件（如果不存在）
    if [ ! -f /etc/init.d/3proxy ]; then
        cat > /etc/init.d/3proxy << 'EOF'
#!/sbin/openrc-run

name="3proxy"
description="Tiny free proxy server"
command="/usr/bin/3proxy"
command_args="/etc/3proxy/3proxy.cfg"
pidfile="/run/${RC_SVCNAME}.pid"
command_background="yes"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --owner root:root --mode 0755 /var/log
}
EOF
        chmod +x /etc/init.d/3proxy
    fi
}

# 创建代理配置
create_proxy_config() {
    local port=$1
    local username=$2
    local password=$3
    
    # 创建配置文件
    cat > "$CONFIG_FILE" << EOF
#!/bin/3proxy
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
    chmod 600 "$CONFIG_FILE"
}

# 配置随机代理
configure_random_proxy() {
    echo "配置随机代理..."
    
    port=$(generate_random_port)
    username=$(generate_random_string 8)
    password=$(generate_random_string 12)
    
    create_proxy_config "$port" "$username" "$password"
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
    restart_proxy
    
    echo "自定义代理已配置完成!"
    view_proxy_info
}

# 重启代理服务
restart_proxy() {
    echo "重启代理服务..."
    if rc-service "$SERVICE_NAME" status >/dev/null 2>&1; then
        rc-service "$SERVICE_NAME" restart
    else
        rc-service "$SERVICE_NAME" start
    fi
    
    # 等待服务启动
    sleep 2
    if rc-service "$SERVICE_NAME" status >/dev/null 2>&1; then
        echo "代理服务已重启!"
    else
        echo "代理服务启动失败，请检查配置。"
    fi
}

# 查看代理信息
view_proxy_info() {
    if [ -f "$CONFIG_INFO" ]; then
        echo "=== 当前代理配置 ==="
        cat "$CONFIG_INFO"
        
        # 显示服务器IP
        echo ""
        echo "服务器IP地址:"
        ip addr | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1
        echo "===================="
        
        # 显示服务状态
        echo "服务状态:"
        rc-service "$SERVICE_NAME" status
        
        # 检查端口是否开放
        PORT=$(grep "socks -p" "$CONFIG_FILE" | sed -E 's/socks -p([0-9]+)/\1/')
        if [ -n "$PORT" ]; then
            echo "端口状态 ($PORT):"
            netstat -tulpn | grep ":$PORT" || echo "端口 $PORT 未开放"
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

# 安装netstat命令
install_netstat() {
    if ! command -v netstat >/dev/null 2>&1; then
        echo "正在安装netstat命令..."
        apk add net-tools
    fi
}

# 主菜单
show_menu() {
    # 如果是通过管道执行，直接自动安装
    if is_pipe_execution; then
        auto_install
        exit 0
    fi

    clear
    echo "===== Alpine Socks5代理配置工具 ====="
    echo "1. 配置随机端口和凭据的代理"
    echo "2. 配置自定义端口和凭据的代理"
    echo "3. 重启代理服务"
    echo "4. 查看当前代理配置"
    echo "5. 检查/重启保活功能"
    echo "0. 退出"
    echo "=============================="
    echo -n "请选择: "
    read -r choice
    
    case $choice in
        1) configure_random_proxy ;;
        2) configure_custom_proxy ;;
        3) restart_proxy ;;
        4) view_proxy_info ;;
        5) setup_keepalive && echo "保活功能已重新配置" ;;
        0) exit 0 ;;
        *) echo "无效选择，请重试。" ;;
    esac
    
    if ! is_pipe_execution; then
        echo ""
        echo "按Enter键继续..."
        read -r
        show_menu
    fi
}

# 自动安装函数
auto_install() {
    echo "正在执行自动安装..."
    install_required_software
    install_netstat
    create_service_script
    setup_keepalive
    configure_random_proxy
    configure_firewall
    echo "安装完成! 代理信息如下:"
    view_proxy_info
}

# 主程序入口
main() {
    # 确保已安装所需软件
    install_required_software
    install_netstat
    
    # 创建服务启动脚本
    create_service_script
    
    # 设置保活功能
    setup_keepalive
    
    # 检查是否有现有配置
    if [ -f "$CONFIG_FILE" ]; then
        echo "检测到现有配置，正在启动服务..."
        restart_proxy
        configure_firewall
        view_proxy_info
        if [ ! is_pipe_execution ] && [ "$1" != "--auto" ]; then
            echo "按Enter键继续..."
            read -r
        fi
    fi
    
    # 检查命令行参数
    if [ "$1" = "--auto" ]; then
        if [ ! -f "$CONFIG_FILE" ]; then
            auto_install
        fi
        exit 0
    fi
    
    # 检查是否通过管道执行
    if is_pipe_execution; then
        auto_install
        exit 0
    fi
    
    # 显示主菜单
    show_menu
}

# 执行主程序
main "$@"

