#!/usr/bin/env bash

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# 默认配置
SERVER_HOST="${SERVER_HOST:-0.0.0.0}"
SERVER_PORT="${SERVER_PORT:-8000}"
DATA_DIR="$PROJECT_ROOT/data"
CONFIG_FILE="$DATA_DIR/config.toml"
TOKEN_FILE="$DATA_DIR/token.json"
DEFAULT_CONFIG="$PROJECT_ROOT/config.defaults.toml"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
Grok2API-rs 运行脚本

用法: $0 [选项]

选项:
    dev         开发模式运行 (cargo run)
    release     生产模式运行 (cargo run --release)
    build       编译 release 版本
    run         运行已编译的二进制文件
    docker      使用 Docker Compose 运行
    clean       清理编译产物
    help        显示此帮助信息

环境变量:
    SERVER_HOST    服务监听地址 (默认: 0.0.0.0)
    SERVER_PORT    服务监听端口 (默认: 8000)

示例:
    $0 dev                    # 开发模式运行
    $0 release                # 生产模式运行
    $0 build                  # 编译 release 版本
    $0 run                    # 运行已编译的二进制
    SERVER_PORT=9000 $0 dev   # 指定端口运行

EOF
}

# 初始化数据目录和配置文件
init_data() {
    log_info "初始化数据目录..."

    # 创建 data 目录
    if [ ! -d "$DATA_DIR" ]; then
        mkdir -p "$DATA_DIR"
        log_success "创建数据目录: $DATA_DIR"
    fi

    # 复制默认配置
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$DEFAULT_CONFIG" ]; then
            cp "$DEFAULT_CONFIG" "$CONFIG_FILE"
            log_success "创建配置文件: $CONFIG_FILE"
        else
            log_error "默认配置文件不存在: $DEFAULT_CONFIG"
            exit 1
        fi
    else
        log_info "配置文件已存在: $CONFIG_FILE"
    fi

    # 创建空的 token.json（如果不存在）
    if [ ! -f "$TOKEN_FILE" ]; then
        echo '{"ssoBasic":[]}' > "$TOKEN_FILE"
        log_success "创建 Token 文件: $TOKEN_FILE"
        log_warn "请在后台管理页面导入 Token: http://${SERVER_HOST}:${SERVER_PORT}/admin"
    else
        log_info "Token 文件已存在: $TOKEN_FILE"
    fi
}

# 检查 Rust 环境
check_rust() {
    if ! command -v cargo &> /dev/null; then
        log_error "未找到 Cargo，请先安装 Rust: https://rustup.rs/"
        exit 1
    fi
}

# 检查编译依赖
check_build_deps() {
    local missing_deps=()

    # 检查 libclang
    if ! dpkg -l | grep -q "libclang-dev"; then
        missing_deps+=("libclang-dev")
    fi

    # 检查 clang
    if ! command -v clang &> /dev/null; then
        missing_deps+=("clang")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warn "缺少编译依赖: ${missing_deps[*]}"
        log_info "正在安装依赖..."

        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y libclang-dev clang
            log_success "依赖安装完成"
        else
            log_error "无法自动安装依赖，请手动安装: ${missing_deps[*]}"
            exit 1
        fi
    fi
}

# 开发模式运行
run_dev() {
    log_info "开发模式运行..."
    init_data
    check_rust
    check_build_deps

    export SERVER_HOST
    export SERVER_PORT

    log_info "服务地址: http://${SERVER_HOST}:${SERVER_PORT}"
    log_info "后台管理: http://127.0.0.1:${SERVER_PORT}/admin"

    cargo run
}

# 生产模式运行
run_release() {
    log_info "生产模式运行..."
    init_data
    check_rust
    check_build_deps

    export SERVER_HOST
    export SERVER_PORT

    log_info "服务地址: http://${SERVER_HOST}:${SERVER_PORT}"
    log_info "后台管理: http://127.0.0.1:${SERVER_PORT}/admin"

    cargo run --release
}

# 编译 release 版本
build_release() {
    log_info "编译 release 版本..."
    check_rust
    check_build_deps

    cargo build --release

    log_success "编译完成: target/release/grok2api-rs"
}

# 运行已编译的二进制
run_binary() {
    log_info "运行已编译的二进制文件..."
    init_data

    BINARY="$PROJECT_ROOT/target/release/grok2api-rs"

    if [ ! -f "$BINARY" ]; then
        log_error "二进制文件不存在: $BINARY"
        log_info "请先运行: $0 build"
        exit 1
    fi

    export SERVER_HOST
    export SERVER_PORT

    log_info "服务地址: http://${SERVER_HOST}:${SERVER_PORT}"
    log_info "后台管理: http://127.0.0.1:${SERVER_PORT}/admin"

    "$BINARY"
}

# Docker Compose 运行
run_docker() {
    log_info "使用 Docker Compose 运行..."

    if ! command -v docker &> /dev/null; then
        log_error "未找到 Docker，请先安装 Docker"
        exit 1
    fi

    init_data

    log_info "拉取最新镜像..."
    docker compose pull

    log_info "启动服务..."
    docker compose up -d

    log_success "服务已启动"
    log_info "查看日志: docker compose logs -f"
    log_info "服务地址: http://127.0.0.1:8000"
    log_info "后台管理: http://127.0.0.1:8000/admin"
}

# 清理编译产物
clean() {
    log_info "清理编译产物..."
    check_rust

    cargo clean

    log_success "清理完成"
}

# 主逻辑
main() {
    case "${1:-dev}" in
        dev)
            run_dev
            ;;
        release)
            run_release
            ;;
        build)
            build_release
            ;;
        run)
            run_binary
            ;;
        docker)
            run_docker
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
