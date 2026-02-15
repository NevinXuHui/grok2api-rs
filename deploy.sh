#!/usr/bin/env bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="grok2api-rs"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARY_SRC="${PROJECT_DIR}/target/release/${SERVICE_NAME}"
BINARY_DST="/usr/local/bin/${SERVICE_NAME}"
DATA_DIR="${PROJECT_DIR}/data"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查 root 权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "请使用 root 或 sudo 运行此脚本"
        exit 1
    fi
}

# 编译 release
build() {
    log_info "编译 release 版本..."
    cd "$PROJECT_DIR"
    cargo build --release
    log_success "编译完成: ${BINARY_SRC}"
}

# 安装二进制
install_binary() {
    log_info "安装二进制到 ${BINARY_DST}..."
    cp "$BINARY_SRC" "$BINARY_DST"
    chmod +x "$BINARY_DST"
    log_success "二进制已安装"
}

# 初始化数据目录
init_data() {
    if [ ! -d "$DATA_DIR" ]; then
        mkdir -p "$DATA_DIR"
        log_success "创建数据目录: ${DATA_DIR}"
    fi
    if [ ! -f "${DATA_DIR}/config.toml" ] && [ -f "${PROJECT_DIR}/config.defaults.toml" ]; then
        cp "${PROJECT_DIR}/config.defaults.toml" "${DATA_DIR}/config.toml"
        log_success "创建默认配置文件"
    fi
    if [ ! -f "${DATA_DIR}/token.json" ]; then
        echo '{"ssoBasic":[]}' > "${DATA_DIR}/token.json"
        log_warn "已创建空 token.json，请通过管理页面导入 Token"
    fi
}

# 创建 systemd service
create_service() {
    log_info "创建 systemd service..."
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Grok2API-rs Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_DIR}
ExecStart=${BINARY_DST}
Restart=on-failure
RestartSec=5
Environment=SERVER_HOST=0.0.0.0
Environment=SERVER_PORT=18966

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    log_success "systemd service 已创建并启用"
}

# 杀掉残留进程
kill_existing() {
    local pids
    pids=$(pgrep -f "$BINARY_DST" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        log_warn "检测到运行中的进程 (PID: ${pids}), 正在终止..."
        kill -9 $pids 2>/dev/null || true
        sleep 1
        log_success "已终止残留进程"
    fi
}

# 主逻辑
main() {
    check_root
    kill_existing
    build
    install_binary
    init_data

    if [ -f "$SERVICE_FILE" ]; then
        log_info "检测到已有 service，重启..."
        systemctl daemon-reload
        systemctl restart "$SERVICE_NAME"
    else
        create_service
        systemctl start "$SERVICE_NAME"
    fi

    log_success "部署完成"
    systemctl status "$SERVICE_NAME" --no-pager
}

main "$@"
