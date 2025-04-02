#!/bin/sh

# 配置文件和日志路径
CONFIG_FILE="/etc/v2ray/config.json"
V2RAY_LOG="/var/log/v2ray/access.log"
CREDENTIALS_FILE="/etc/v2ray/credentials.txt"
KEEPALIVE_SERVICE="/etc/init.d/v2ray-keepalive"

# 颜色定义
GREEN="\033[0;32m"
BLUE="\033[0;34m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
PURPLE="\033[0;35m"
CYAN="\033[0;36m"
WHITE="\033[1;37m"
NC="\033[0m" # 无颜色

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误: 请使用root权限运行此脚本!${NC}"
        exit 1
    fi
}

# 安装必要的软件包
install_dependencies() {
    echo -e "${BLUE}正在检查并安装依赖项...${NC}"
    
    # 更新软件包索引
    if ! apk update; then
        echo -e "${RED}更新软件包索引失败${NC}"
        return 1
    fi
    
    # 安装基本工具
    echo -e "${BLUE}安装基础工具...${NC}"
    if ! apk add --no-cache curl jq openrc; then
        echo -e "${RED}安装基础工具失败${NC}"
        return 1
    fi
    
    # 安装V2Ray - 单独安装以便捕获错误
    echo -e "${BLUE}安装V2Ray...${NC}"
    if ! apk add --no-cache v2ray; then
        echo -e "${RED}安装V2Ray失败。可能是由于内存不足或网络问题。${NC}"
        return 1
    fi
    
    # 创建必要的目录
    mkdir -p /etc/v2ray
    mkdir -p /var/log/v2ray
    
    # 检查V2Ray服务是否存在
    if ! ls /etc/init.d/v2ray >/dev/null 2>&1; then
        echo -e "${RED}找不到V2Ray服务。尝试手动创建服务文件...${NC}"
        
        # 创建简单的v2ray服务文件
        cat > /etc/init.d/v2ray << 'EOF'
#!/sbin/openrc-run

name="V2Ray"
description="V2Ray Service"
command="/usr/bin/v2ray"
command_args="run -config /etc/v2ray/config.json"
pidfile="/var/run/v2ray.pid"
command_background="yes"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -d -m 0755 -o root:root /var/log/v2ray
}
EOF
        chmod +x /etc/init.d/v2ray
    fi
    
    # 启用V2Ray服务
    if ! rc-update add v2ray default; then
        echo -e "${RED}无法启用V2Ray服务。继续但某些功能可能无法工作。${NC}"
    fi
    
    echo -e "${GREEN}依赖安装完成${NC}"
    return 0
}

# 验证V2Ray是否正确安装
verify_v2ray() {
    if ! command -v v2ray >/dev/null 2>&1; then
        echo -e "${RED}V2Ray未安装或不在PATH中。${NC}"
        return 1
    fi
    
    if ! [ -f /etc/init.d/v2ray ]; then
        echo -e "${RED}找不到V2Ray服务文件。${NC}"
        return 1
    fi
    
    echo -e "${GREEN}V2Ray安装验证通过${NC}"
    return 0
}

# 生成随机端口(1024-65535)
generate_random_port() {
    echo $(( (RANDOM % 64511) + 1024 ))
}

# 生成随机用户名和密码
generate_random_credentials() {
    local username=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 8)
    local password=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 12)
    echo "$username:$password"
}

# 保存凭据到文件
save_credentials() {
    local port=$1
    local username=$2
    local password=$3
    
    echo "端口: $port" > "$CREDENTIALS_FILE"
    echo "用户名: $username" >> "$CREDENTIALS_FILE"
    echo "密码: $password" >> "$CREDENTIALS_FILE"
    
    chmod 600 "$CREDENTIALS_FILE"
    
    echo -e "${GREEN}凭据已保存到 $CREDENTIALS_FILE${NC}"
}

# 配置V2Ray
configure_v2ray() {
    local port=$1
    local username=$2
    local password=$3
    
    # 确保目录存在
    mkdir -p /etc/v2ray
    
    cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": $port,
      "protocol": "socks",
      "settings": {
        "auth": "password",
        "accounts": [
          {
            "user": "$username",
            "pass": "$password"
          }
        ],
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF

    echo -e "${GREEN}V2Ray已配置为使用端口 $port 和用户名/密码认证${NC}"
    save_credentials "$port" "$username" "$password"
}

# 重启V2Ray服务
restart_v2ray() {
    echo -e "${BLUE}正在重启V2Ray服务...${NC}"
    
    # 检查服务文件是否存在
    if [ ! -f /etc/init.d/v2ray ]; then
        echo -e "${RED}V2Ray服务不存在，无法重启。${NC}"
        return 1
    fi
    
    # 尝试重启服务
    rc-service v2ray restart
    
    # 检查服务状态
    if rc-service v2ray status | grep -q "started"; then
        echo -e "${GREEN}V2Ray服务已成功重启${NC}"
        return 0
    else
        echo -e "${YELLOW}通过服务管理器重启失败，尝试手动启动...${NC}"
        
        # 如果服务启动失败，尝试手动启动
        if [ -f "$CONFIG_FILE" ]; then
            killall v2ray 2>/dev/null
            nohup v2ray run -config "$CONFIG_FILE" > /var/log/v2ray/v2ray.log 2>&1 &
            sleep 2
            
            if pgrep -x v2ray > /dev/null; then
                echo -e "${GREEN}V2Ray已手动启动${NC}"
                return 0
            else
                echo -e "${RED}V2Ray手动启动失败${NC}"
                return 1
            fi
        else
            echo -e "${RED}找不到配置文件，请先配置V2Ray${NC}"
            return 1
        fi
    fi
}

# 停止V2Ray服务
stop_v2ray() {
    echo -e "${BLUE}正在停止V2Ray服务...${NC}"
    
    # 首先尝试使用服务脚本停止
    if [ -f /etc/init.d/v2ray ]; then
        if rc-service v2ray stop; then
            echo -e "${GREEN}V2Ray服务已停止${NC}"
        else
            echo -e "${YELLOW}通过服务管理器停止失败，尝试手动停止...${NC}"
            killall v2ray 2>/dev/null
            if ! pgrep -x v2ray > /dev/null; then
                echo -e "${GREEN}V2Ray已手动停止${NC}"
            else
                echo -e "${RED}无法停止V2Ray服务${NC}"
                return 1
            fi
        fi
    else
        # 如果没有服务脚本，直接尝试杀死进程
        if pgrep -x v2ray > /dev/null; then
            killall v2ray
            if ! pgrep -x v2ray > /dev/null; then
                echo -e "${GREEN}V2Ray已停止${NC}"
            else
                echo -e "${RED}无法停止V2Ray服务${NC}"
                return 1
            fi
        else
            echo -e "${YELLOW}V2Ray服务已经是停止状态${NC}"
        fi
    fi
    
    return 0
}

# 卸载V2Ray
uninstall_v2ray() {
    echo -e "${YELLOW}警告: 此操作将卸载V2Ray并删除所有相关配置！${NC}"
    echo -e "${YELLOW}是否继续? (y/n)${NC}"
    read -r choice
    
    if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
        echo -e "${BLUE}卸载已取消${NC}"
        return 0
    fi
    
    # 停止并禁用服务
    if [ -f /etc/init.d/v2ray ]; then
        echo -e "${BLUE}停止V2Ray服务...${NC}"
        rc-service v2ray stop 2>/dev/null
        echo -e "${BLUE}禁用V2Ray服务...${NC}"
        rc-update del v2ray default 2>/dev/null
    fi
    
    # 停止并禁用保活服务
    if [ -f "$KEEPALIVE_SERVICE" ]; then
        echo -e "${BLUE}停止保活服务...${NC}"
        rc-service v2ray-keepalive stop 2>/dev/null
        echo -e "${BLUE}禁用保活服务...${NC}"
        rc-update del v2ray-keepalive default 2>/dev/null
        rm -f "$KEEPALIVE_SERVICE"
        rm -f /usr/local/bin/v2ray-keepalive.sh
    fi
    
    # 终止所有V2Ray进程
    echo -e "${BLUE}终止V2Ray进程...${NC}"
    killall v2ray 2>/dev/null
    
    # 卸载软件包
    echo -e "${BLUE}卸载V2Ray软件包...${NC}"
    apk del v2ray
    
    # 删除配置文件和日志
    echo -e "${BLUE}删除配置文件和日志...${NC}"
    rm -rf /etc/v2ray
    rm -rf /var/log/v2ray
    
    # 删除手动安装的文件
    rm -f /usr/bin/v2ray
    rm -f /usr/bin/v2ctl
    rm -f /etc/init.d/v2ray
    
    echo -e "${GREEN}V2Ray已成功卸载${NC}"
    return 0
}

# 设置自动保活脚本
setup_keepalive() {
    cat > "$KEEPALIVE_SERVICE" << 'EOF'
#!/sbin/openrc-run

name="V2Ray Keepalive"
description="Keep V2Ray service alive"

depend() {
    need net
    after v2ray
}

start() {
    ebegin "Starting V2Ray keepalive service"
    
    # 创建保活脚本
    cat > /usr/local/bin/v2ray-keepalive.sh << 'INNEREOF'
#!/bin/sh
while true; do
    if ! pgrep -x v2ray > /dev/null; then
        echo "V2Ray is down, restarting..."
        rc-service v2ray restart
        # 如果服务重启失败，尝试手动启动
        if ! pgrep -x v2ray > /dev/null; then
            if [ -f /etc/v2ray/config.json ]; then
                v2ray run -config /etc/v2ray/config.json > /var/log/v2ray/v2ray.log 2>&1 &
                echo "Manually restarted V2Ray"
            fi
        fi
    fi
    sleep 60
done
INNEREOF
    
    chmod +x /usr/local/bin/v2ray-keepalive.sh
    
    start-stop-daemon --start --background \
        --make-pidfile --pidfile /var/run/v2ray-keepalive.pid \
        --exec /usr/local/bin/v2ray-keepalive.sh
    
    eend $?
}

stop() {
    ebegin "Stopping V2Ray keepalive service"
    start-stop-daemon --stop --pidfile /var/run/v2ray-keepalive.pid
    eend $?
}
EOF

    chmod +x "$KEEPALIVE_SERVICE"
    rc-update add v2ray-keepalive default
    rc-service v2ray-keepalive start
    
    echo -e "${GREEN}V2Ray保活服务已设置并启动${NC}"
}

# 检查并重启保活服务
check_keepalive() {
    if [ -f "$KEEPALIVE_SERVICE" ]; then
        if rc-service v2ray-keepalive status 2>/dev/null | grep -q "started"; then
            echo -e "${GREEN}V2Ray保活服务正在运行${NC}"
            
            echo -e "${YELLOW}是否要重启保活服务? (y/n)${NC}"
            read -r choice
            if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
                rc-service v2ray-keepalive restart
                echo -e "${GREEN}保活服务已重启${NC}"
            fi
        else
            echo -e "${RED}V2Ray保活服务未运行${NC}"
            echo -e "${YELLOW}是否要启动保活服务? (y/n)${NC}"
            read -r choice
            if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
                rc-service v2ray-keepalive start
                echo -e "${GREEN}保活服务已启动${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}未找到保活服务，是否要设置? (y/n)${NC}"
        read -r choice
        if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
            setup_keepalive
        fi
    fi
}

# 显示当前配置
show_current_config() {
    echo -e "${CYAN}╭───────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${WHITE}          当前V2Ray Socks5代理配置          ${CYAN}│${NC}"
    echo -e "${CYAN}╰───────────────────────────────────────────╯${NC}"
    
    if [ -f "$CREDENTIALS_FILE" ]; then
        # 读取配置信息
        local port=$(grep "端口:" "$CREDENTIALS_FILE" | cut -d' ' -f2)
        local username=$(grep "用户名:" "$CREDENTIALS_FILE" | cut -d' ' -f2)
        local password=$(grep "密码:" "$CREDENTIALS_FILE" | cut -d' ' -f2)
        
        echo -e "${BLUE}端口:    ${WHITE}$port${NC}"
        echo -e "${BLUE}用户名:  ${WHITE}$username${NC}"
        echo -e "${BLUE}密码:    ${WHITE}$password${NC}"
        
        # 显示运行状态
        if pgrep -x v2ray > /dev/null; then
            echo -e "${BLUE}状态:    ${GREEN}运行中${NC}"
        else
            echo -e "${BLUE}状态:    ${RED}未运行${NC}"
        fi
        
        # 显示IP地址
        echo -e "${BLUE}服务器IP地址:${NC}"
        ip -4 addr show | grep -o "inet [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" | grep -v "127.0.0.1" | sed 's/inet //' | head -n 1
        
        # 显示连接信息
        echo -e "${CYAN}╭───────────────────────────────────────────╮${NC}"
        echo -e "${CYAN}│${WHITE}               连接信息                   ${CYAN}│${NC}"
        echo -e "${CYAN}╰───────────────────────────────────────────╯${NC}"
        echo -e "${YELLOW}协议:    ${WHITE}SOCKS5${NC}"
        echo -e "${YELLOW}地址:    ${WHITE}$(ip -4 addr show | grep -o "inet [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" | grep -v "127.0.0.1" | sed 's/inet //' | head -n 1)${NC}"
        echo -e "${YELLOW}端口:    ${WHITE}$port${NC}"
        echo -e "${YELLOW}用户名:  ${WHITE}$username${NC}"
        echo -e "${YELLOW}密码:    ${WHITE}$password${NC}"
    else
        echo -e "${YELLOW}未找到配置文件，请先配置代理${NC}"
    fi
}

# 显示服务日志
show_logs() {
    echo -e "${CYAN}╭───────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${WHITE}              V2Ray服务日志              ${CYAN}│${NC}"
    echo -e "${CYAN}╰───────────────────────────────────────────╯${NC}"
    
    if [ -f "$V2RAY_LOG" ]; then
        echo -e "${BLUE}显示最近50行V2Ray日志:${NC}"
        tail -n 50 "$V2RAY_LOG"
    else
        echo -e "${YELLOW}V2Ray访问日志文件不存在${NC}"
        
        # 检查是否有手动启动的日志
        if [ -f "/var/log/v2ray/v2ray.log" ]; then
            echo -e "${BLUE}显示手动启动的V2Ray日志:${NC}"
            tail -n 50 "/var/log/v2ray/v2ray.log"
        fi
    fi
    
    echo -e "${YELLOW}按Enter键返回主菜单${NC}"
    read -r
}

# 配置随机端口和凭据
configure_random() {
    if ! verify_v2ray; then
        echo -e "${YELLOW}V2Ray可能未正确安装，配置可能不会正常工作。${NC}"
        echo -e "${YELLOW}是否继续? (y/n)${NC}"
        read -r choice
        if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
            return
        fi
    fi
    
    local port=$(generate_random_port)
    local credentials=$(generate_random_credentials)
    local username=$(echo "$credentials" | cut -d: -f1)
    local password=$(echo "$credentials" | cut -d: -f2)
    
    configure_v2ray "$port" "$username" "$password"
    restart_v2ray
    
    echo -e "${GREEN}已配置随机端口和凭据的V2Ray Socks5代理${NC}"
    
    # 美化显示配置信息
    echo -e "${CYAN}╭───────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${WHITE}            新配置的代理信息               ${CYAN}│${NC}"
    echo -e "${CYAN}╰───────────────────────────────────────────╯${NC}"
    echo -e "${YELLOW}端口:    ${WHITE}$port${NC}"
    echo -e "${YELLOW}用户名:  ${WHITE}$username${NC}"
    echo -e "${YELLOW}密码:    ${WHITE}$password${NC}"
}

# 配置自定义端口和凭据
configure_custom() {
    if ! verify_v2ray; then
        echo -e "${YELLOW}V2Ray可能未正确安装，配置可能不会正常工作。${NC}"
        echo -e "${YELLOW}是否继续? (y/n)${NC}"
        read -r choice
        if [ "$choice" != "y" ] && [ "$choice" != "Y" ]; then
            return
        fi
    fi
    
    echo -e "${CYAN}╭───────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${WHITE}            自定义代理配置                ${CYAN}│${NC}"
    echo -e "${CYAN}╰───────────────────────────────────────────╯${NC}"
    
    # 是否自动生成用户名和密码
    echo -e "${YELLOW}是否自动生成用户名和密码? (y/n)${NC}"
    read -r auto_gen
    
    # 端口输入或生成
    echo -e "${BLUE}请输入端口号 (1024-65535) 或按Enter使用随机端口: ${NC}"
    read -r port
    
    # 如果端口为空或无效，则生成随机端口
    if [ -z "$port" ] || ! echo "$port" | grep -qE '^[0-9]+$' || [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
        port=$(generate_random_port)
        echo -e "${GREEN}已生成随机端口: $port${NC}"
    fi
    
    # 根据选择处理用户名和密码
    if [ "$auto_gen" = "y" ] || [ "$auto_gen" = "Y" ]; then
        local credentials=$(generate_random_credentials)
        username=$(echo "$credentials" | cut -d: -f1)
        password=$(echo "$credentials" | cut -d: -f2)
        
        echo -e "${GREEN}已生成随机用户名: $username${NC}"
        echo -e "${GREEN}已生成随机密码: $password${NC}"
    else
        # 用户名输入
        echo -e "${BLUE}请输入用户名: ${NC}"
        read -r username
        
        # 验证用户名
        if [ -z "$username" ]; then
            echo -e "${RED}用户名不能为空${NC}"
            return 1
        fi
        
        # 密码输入
        echo -e "${BLUE}请输入密码: ${NC}"
        read -r password
        
        # 验证密码
        if [ -z "$password" ]; then
            echo -e "${RED}密码不能为空${NC}"
            return 1
        fi
    fi
    
    configure_v2ray "$port" "$username" "$password"
    restart_v2ray
    
    echo -e "${GREEN}已配置自定义V2Ray Socks5代理${NC}"
    
    # 美化显示配置信息
    echo -e "${CYAN}╭───────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${WHITE}            新配置的代理信息               ${CYAN}│${NC}"
    echo -e "${CYAN}╰───────────────────────────────────────────╯${NC}"
    echo -e "${YELLOW}端口:    ${WHITE}$port${NC}"
    echo -e "${YELLOW}用户名:  ${WHITE}$username${NC}"
    echo -e "${YELLOW}密码:    ${WHITE}$password${NC}"
}

# 手动下载V2Ray
manual_install_v2ray() {
    echo -e "${BLUE}尝试手动安装V2Ray...${NC}"
    
    # 创建目录
    mkdir -p /usr/bin
    mkdir -p /etc/v2ray
    mkdir -p /var/log/v2ray
    
    # 下载V2Ray二进制文件
    echo -e "${BLUE}下载V2Ray二进制文件...${NC}"
    local arch=$(uname -m)
    local v2ray_url="https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-64.zip"
    
    if [ "$arch" = "aarch64" ]; then
        v2ray_url="https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-arm64-v8a.zip"
    elif [ "$arch" = "armv7l" ]; then
        v2ray_url="https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-arm32-v7a.zip"
    fi
    
    # 下载并解压
    cd /tmp
    if ! curl -L -o v2ray.zip "$v2ray_url"; then
        echo -e "${RED}下载V2Ray失败${NC}"
        return 1
    fi
    
    # 确保有unzip工具
    apk add --no-cache unzip
    
    # 解压文件
    unzip -o v2ray.zip -d /tmp/v2ray
    
    # 移动文件
    cp /tmp/v2ray/v2ray /usr/bin/
    cp /tmp/v2ray/v2ctl /usr/bin/ 2>/dev/null || true  # 某些版本可能没有v2ctl
    cp /tmp/v2ray/geoip.dat /usr/bin/ 2>/dev/null || true
    cp /tmp/v2ray/geosite.dat /usr/bin/ 2>/dev/null || true
    
    # 清理
    rm -rf /tmp/v2ray
    rm -f /tmp/v2ray.zip
    
    # 设置执行权限
    chmod +x /usr/bin/v2ray
    chmod +x /usr/bin/v2ctl 2>/dev/null || true
    
    # 创建服务文件
    cat > /etc/init.d/v2ray << 'EOF'
#!/sbin/openrc-run

name="V2Ray"
description="V2Ray Service"
command="/usr/bin/v2ray"
command_args="run -config /etc/v2ray/config.json"
pidfile="/var/run/v2ray.pid"
command_background="yes"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath -d -m 0755 -o root:root /var/log/v2ray
}
EOF

    chmod +x /etc/init.d/v2ray
    
    # 启用服务
    rc-update add v2ray default
    
    echo -e "${GREEN}V2Ray手动安装完成${NC}"
    verify_v2ray
}

# 绘制菜单
draw_menu() {
    clear
    echo -e "${CYAN}╭───────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${WHITE}      Alpine V2Ray Socks5代理配置工具       ${CYAN}│${NC}"
    echo -e "${CYAN}│${BLUE}       作者: crazykfc     版本: 1.0.0      ${CYAN}│${NC}"
    echo -e "${CYAN}╰───────────────────────────────────────────╯${NC}"
    echo
    echo -e "${WHITE}【代理配置】${NC}"
    echo -e "  ${GREEN}1.${NC} 配置随机端口和凭据的代理"
    echo -e "  ${GREEN}2.${NC} 配置自定义端口和凭据的代理"
    echo
    echo -e "${WHITE}【服务管理】${NC}"
    echo -e "  ${GREEN}3.${NC} 重启代理服务"
    echo -e "  ${GREEN}4.${NC} 停止代理服务"
    echo -e "  ${GREEN}5.${NC} 查看当前代理配置"
    echo -e "  ${GREEN}6.${NC} 检查/重启保活功能"
    echo -e "  ${GREEN}7.${NC} 检查服务日志"
    echo
    echo -e "${WHITE}【系统维护】${NC}"
    echo -e "  ${GREEN}8.${NC} 手动安装V2Ray"
    echo -e "  ${GREEN}9.${NC} 卸载V2Ray及所有配置"
    echo -e "  ${GREEN}0.${NC} 退出"
    echo
    echo -e "${YELLOW}请输入选项 [0-9]:${NC} "
}

# 显示主菜单
show_menu() {
    draw_menu
    read -r choice
    
    case "$choice" in
        1) configure_random ;;
        2) configure_custom ;;
        3) restart_v2ray ;;
        4) stop_v2ray ;;
        5) show_current_config ;;
        6) check_keepalive ;;
        7) show_logs ;;
        8) manual_install_v2ray ;;
        9) uninstall_v2ray ;;
        0) echo -e "${GREEN}谢谢使用，再见!${NC}"; exit 0 ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
    
    echo
    echo -e "${YELLOW}按Enter键继续...${NC}"
    read -r
}

# 主函数
main() {
    check_root
    install_dependencies
    
    # 检查安装结果
    if ! verify_v2ray; then
        echo -e "${YELLOW}警告: V2Ray似乎未正确安装。${NC}"
        echo -e "${YELLOW}您可以选择:${NC}"
        echo -e "${BLUE}1.${NC} 尝试手动安装V2Ray"
        echo -e "${BLUE}2.${NC} 继续使用（某些功能可能无法工作）"
        echo -e "${YELLOW}请选择 [1-2]:${NC}"
        read -r install_choice
        
        if [ "$install_choice" = "1" ]; then
            manual_install_v2ray
        else
            echo -e "${YELLOW}继续，但某些功能可能无法正常工作${NC}"
        fi
    fi
    
    while true; do
        show_menu
    done
}

# 启动脚本
main
