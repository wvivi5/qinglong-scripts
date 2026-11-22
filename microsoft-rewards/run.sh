#!/usr/bin/env bash
# QingLong entry: do not send account requests until both browser credentials exist.
set -eu
export REWARDS_DATA_DIR="${REWARDS_DATA_DIR:-/ql/data/rewards-data}"
export REWARDS_NOTIFY="${REWARDS_NOTIFY:-1}"
# 网页通道（搜索/活动）在当前环境不可用（rewards.bing.com 一律 302 到 /Signin），
# 默认关闭，避免每小时失败并刷屏通知。需要时可显式设成 1 覆盖。
export REWARDS_SEARCH="${REWARDS_SEARCH:-0}"
export REWARDS_PROMO="${REWARDS_PROMO:-0}"
[ -f /ql/data/config/config.sh ] && . /ql/data/config/config.sh
# 青龙执行 task 时 $0 可能不带目录，导致 dirname 算错；优先用固定路径，并做多路径兜底。
script_dir=""
for _d in /ql/data/scripts/microsoft-rewards /ql/scripts/microsoft-rewards "$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)"; do
  if [ -n "$_d" ] && [ -f "$_d/rewards.js" ]; then script_dir="$_d"; break; fi
done
if [ -z "$script_dir" ]; then
  printf '%s\n' '找不到 rewards.js，请检查脚本目录是否完整。'
  exit 1
fi
printf '%s\n' "脚本目录: $script_dir"
# 仅 App 端（签到/阅读）时不需要浏览器 Cookie，只要有 refresh_token 即可运行。
# 若开启了网页功能（REWARDS_SEARCH / REWARDS_PROMO 非 0），才要求 Cookie 非空。
if ! node -e '
const fs=require("node:fs"),path=require("node:path");
const needWeb = String(process.env.REWARDS_SEARCH||"1") !== "0" || String(process.env.REWARDS_PROMO||"1") !== "0";
try{
  const c=JSON.parse(fs.readFileSync(path.join(process.env.REWARDS_DATA_DIR,"credentials.json")));
  const hasApp = Boolean(c.app && c.app.refresh_token);
  const hasCookie = Array.isArray(c.cookies) && c.cookies.length > 0;
  if (!hasApp) process.exit(1);
  if (needWeb && !hasCookie) process.exit(1);
  process.exit(0);
}catch{ process.exit(1); }
'; then
  printf '%s\n' '缺少 App 授权（refresh_token），或已开启网页功能但缺少 Cookie；本轮不发起微软任务。'
  exit 0
fi
exec node "$script_dir/rewards.js"
