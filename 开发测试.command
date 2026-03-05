#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMP_DIR="${PROJECT_DIR}/temp/dev-test"
CONFIG_SRC="${PROJECT_DIR}/config.yaml"
CONFIG_DST="${TEMP_DIR}/config.dev-test.yaml"
MANAGEMENT_PASSWORD_VALUE="${DEV_MANAGEMENT_PASSWORD:-dev-local-123}"
BASE_PORT="${DEV_BASE_PORT:-8318}"
FORCE_PORT="${DEV_PORT:-}"
DRY_RUN=false
PRINT_CONFIG=false

log() {
  echo "[CLIProxyAPI 开发测试] $*"
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

port_in_use() {
  local port="$1"
  if command_exists lsof; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  if command_exists ss; then
    ss -ltn "sport = :${port}" | awk 'NR>1 {exit 0} END {exit 1}'
    return $?
  fi
  if command_exists netstat; then
    netstat -an 2>/dev/null | grep -E "[\\.:]${port}[[:space:]]" | grep -qi LISTEN
    return $?
  fi
  return 1
}

choose_port() {
  if [[ -n "${FORCE_PORT}" ]]; then
    if port_in_use "${FORCE_PORT}"; then
      echo "指定端口 ${FORCE_PORT} 已被占用，请更换 DEV_PORT" >&2
      exit 1
    fi
    echo "${FORCE_PORT}"
    return
  fi

  local p
  for ((p=BASE_PORT; p<BASE_PORT+200; p++)); do
    if ! port_in_use "${p}"; then
      echo "${p}"
      return
    fi
  done

  echo "从 ${BASE_PORT} 开始未找到可用端口，请关闭占用进程后重试" >&2
  exit 1
}

render_config() {
  local selected_port="$1"

  awk \
    -v selected_port="${selected_port}" '
      BEGIN {
        host_seen=0
        port_seen=0
      }

      {
        if ($0 ~ /^host:[[:space:]]*/) {
          host_seen=1
          print "host: \"127.0.0.1\""
          next
        }

        if ($0 ~ /^port:[[:space:]]*/) {
          port_seen=1
          print "port: " selected_port
          next
        }

        print
      }

      END {
        if (!host_seen) print "host: \"127.0.0.1\""
        if (!port_seen) print "port: " selected_port
      }
    ' "${CONFIG_SRC}" > "${CONFIG_DST}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      ;;
    --print-config)
      PRINT_CONFIG=true
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [--dry-run] [--print-config]" >&2
      exit 1
      ;;
  esac
  shift
done

if ! command_exists go; then
  log "未检测到 go，请先安装 Go 后重试。"
  pause_and_exit 1
fi

if [[ ! -f "${CONFIG_SRC}" ]]; then
  if [[ -f "${PROJECT_DIR}/config.example.yaml" ]]; then
    CONFIG_SRC="${PROJECT_DIR}/config.example.yaml"
    log "未找到 config.yaml，使用 config.example.yaml 作为模板。"
  else
    log "未找到 config.yaml / config.example.yaml。"
    pause_and_exit 1
  fi
fi

mkdir -p "${TEMP_DIR}"
SELECTED_PORT="$(choose_port)"
render_config "${SELECTED_PORT}"

BASE_URL="http://127.0.0.1:${SELECTED_PORT}"
MANAGEMENT_URL="${BASE_URL}/management.html"
BRANCH_NAME="$(git -C "${PROJECT_DIR}" branch --show-current 2>/dev/null || true)"

if [[ "${PRINT_CONFIG}" == "true" ]]; then
  echo "===== ${CONFIG_DST} ====="
  cat "${CONFIG_DST}"
  echo "=========================="
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  log "[dry-run] 配置模板: ${CONFIG_SRC}"
  log "[dry-run] 临时配置: ${CONFIG_DST}"
  log "[dry-run] 启动端口: ${SELECTED_PORT}"
  log "[dry-run] 管理密码: ${MANAGEMENT_PASSWORD_VALUE}"
  exit 0
fi

echo ""
log "正在启动 CLIProxyAPI 开发测试模式..."
if [[ -n "${BRANCH_NAME}" ]]; then
  log "分支: ${BRANCH_NAME}"
fi
log "配置模板: ${CONFIG_SRC}"
log "临时配置: ${CONFIG_DST}"
log "端口: ${SELECTED_PORT}"
log "API 地址: ${BASE_URL}"
log "管理页面: ${MANAGEMENT_URL}"
log "管理密码: ${MANAGEMENT_PASSWORD_VALUE}"
log "按 Ctrl+C 停止服务"
echo "---"

cd "${PROJECT_DIR}"
MANAGEMENT_PASSWORD="${MANAGEMENT_PASSWORD_VALUE}" go run ./cmd/server -config "${CONFIG_DST}"
EXIT_CODE=$?

if [[ ${EXIT_CODE} -ne 0 ]]; then
  log "服务异常退出，退出码: ${EXIT_CODE}"
  pause_and_exit ${EXIT_CODE}
fi
