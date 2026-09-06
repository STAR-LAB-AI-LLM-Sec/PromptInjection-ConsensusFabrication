#!/usr/bin/env bash
# =============================================================================
# 防守方终端脚本 —— ChatOps 团队协作助手攻防基准（Baseline：多源共识来源校验中介）
#
# 交互式配置：真实大模型 Agent API（输入 y）/ 离线确定性规则 Agent 模拟器（输入 N，默认）
#
# 在新机器上以默认参数运行：
#     pip install -r requirements.txt
#     bash run_defense.sh
#
# 输出：ConsensusSourceGuard 面对全部官方攻击的防御胜率、误伤率与资格线判定
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# 指定解释器：默认 python，可用 PYTHON 环境变量覆盖
PY="${PYTHON:-python}"

echo ">>> [run_defense] 防守方 Baseline 评测（ConsensusSourceGuard）"
read -rp "使用真实大模型 Agent API 评测？[y/N] " USE_API
if [[ "${USE_API:-}" =~ ^[Yy] ]]; then
    echo ">>> 交互式配置 OpenAI 兼容 Agent API（可先用环境变量预填：AGENT_BASE_URL / AGENT_API_KEY / AGENT_MODEL）"
    read -rp "Agent Base URL (默认 https://api.openai.com/v1): " AGENT_BASE_URL
    AGENT_BASE_URL="${AGENT_BASE_URL:-https://api.openai.com/v1}"
    read -rp "API Key (回车则使用环境变量 AGENT_API_KEY): " AGENT_API_KEY
    read -rp "Model ID (默认 gpt-4o-mini): " AGENT_MODEL
    AGENT_MODEL="${AGENT_MODEL:-gpt-4o-mini}"
    export AGENT_BASE_URL AGENT_API_KEY AGENT_MODEL
    "$PY" test.py --stage defense --judge api
else
    echo ">>> 离线模拟 Agent（无需 API，秒级跑通；真实模型请选择 y）"
    "$PY" test.py --stage defense --judge mock
fi
