#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BOOTSTRAP_DIR="$PROJECT_DIR/temp/.bootstrap"
BOOTSTRAP_MARKER="$BOOTSTRAP_DIR/deps_ready"
SERVER_PID=""

log() {
  echo "[CLIProxyAPI Launcher] $*"
}

print_link() {
  local label="$1"
  local url="$2"
  # OSC 8 hyperlink for iTerm2/modern terminals; keep raw URL for compatibility.
  printf '[CLIProxyAPI Launcher] %s: \033]8;;%s\033\\%s\033]8;;\033\\ (%s)\n' "$label" "$url" "$url" "$url"
}

pause_and_exit() {
  local code="${1:-1}"
  echo
  read -r -p "按回车键退出..." _
  exit "$code"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

ensure_go() {
  if command_exists go; then
    return 0
  fi

  log "未检测到 Go，尝试使用 Homebrew 自动安装..."
  if ! command_exists brew; then
    log "未检测到 Homebrew，无法自动安装 Go。"
    log "请先安装 Homebrew（https://brew.sh）或 Go（https://go.dev/dl）。"
    pause_and_exit 1
  fi

  brew install go
}

ensure_config_files() {
  if [[ ! -f "$PROJECT_DIR/config.yaml" && -f "$PROJECT_DIR/config.example.yaml" ]]; then
    cp "$PROJECT_DIR/config.example.yaml" "$PROJECT_DIR/config.yaml"
    log "首次运行已创建 config.yaml（来自 config.example.yaml）。"
  fi

  if [[ ! -f "$PROJECT_DIR/.env" && -f "$PROJECT_DIR/.env.example" ]]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    log "首次运行已创建 .env（来自 .env.example）。"
  fi
}

bootstrap_dependencies() {
  mkdir -p "$BOOTSTRAP_DIR"

  if [[ -f "$BOOTSTRAP_MARKER" ]]; then
    if [[ "$PROJECT_DIR/go.mod" -nt "$BOOTSTRAP_MARKER" || "$PROJECT_DIR/go.sum" -nt "$BOOTSTRAP_MARKER" ]]; then
      log "检测到依赖清单更新，重新安装依赖..."
      (cd "$PROJECT_DIR" && go mod download)
      touch "$BOOTSTRAP_MARKER"
    fi
    return 0
  fi

  log "首次运行，开始安装依赖..."
  (cd "$PROJECT_DIR" && go mod download)
  ensure_config_files
  touch "$BOOTSTRAP_MARKER"
  log "首次初始化完成。"
}

get_config_port() {
  local port
  port="$(awk -F: '/^[[:space:]]*port:[[:space:]]*[0-9]+/{gsub(/[[:space:]]/, "", $2); print $2; exit}' "$PROJECT_DIR/config.yaml" 2>/dev/null || true)"
  if [[ -z "${port}" ]]; then
    port="8317"
  fi
  echo "$port"
}

has_management_secret() {
  local value
  value="$(
    awk '
      BEGIN { in_rm=0 }
      /^[[:space:]]*remote-management:[[:space:]]*$/ { in_rm=1; next }
      in_rm && /^[^[:space:]]/ { in_rm=0 }
      in_rm && /^[[:space:]]*secret-key:[[:space:]]*/ {
        sub(/^[[:space:]]*secret-key:[[:space:]]*/, "", $0)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
        gsub(/^"|"$/, "", $0)
        gsub(/^'\''|'\''$/, "", $0)
        print $0
        exit
      }
    ' "$PROJECT_DIR/config.yaml" 2>/dev/null || true
  )"

  [[ -n "${value}" ]]
}

wait_for_server_ready() {
  local base_url="$1"
  local retries=60
  local i

  if ! command_exists curl; then
    return 0
  fi

  for ((i=0; i<retries; i++)); do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      return 1
    fi
    if curl -fsS "${base_url}/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done

  return 1
}

cleanup() {
  local code=$?
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  exit "$code"
}

start_server() {
  cd "$PROJECT_DIR"
  local port base_url management_url
  port="$(get_config_port)"
  base_url="http://127.0.0.1:${port}"
  management_url="${base_url}/management.html"

  log "正在启动 CLIProxyAPI..."
  print_link "API 地址" "${base_url}"
  print_link "管理页面" "${management_url}"
  if has_management_secret; then
    log "管理密钥已配置，可在管理页面登录。"
  else
    log "未配置 remote-management.secret-key，管理 API 仍是禁用状态。"
  fi
  log "停止服务请按 Ctrl+C。"

  trap cleanup INT TERM
  go run ./cmd/server &
  SERVER_PID="$!"

  if wait_for_server_ready "$base_url"; then
    log "服务已就绪。"
    log "请在终端中按住 Command 并点击上面的管理页面地址打开浏览器。"
  else
    log "服务启动失败或超时，请检查上方日志。"
    wait "$SERVER_PID" || true
    pause_and_exit 1
  fi

  wait "$SERVER_PID"
}

main() {
  ensure_go
  bootstrap_dependencies
  start_server
}

main || pause_and_exit 1
