#!/usr/bin/env bash
# QingLong entry: do not send account requests until both browser credentials exist.
set -eu
export REWARDS_DATA_DIR="${REWARDS_DATA_DIR:-/ql/data/rewards-data}"
export REWARDS_NOTIFY="${REWARDS_NOTIFY:-1}"
[ -f /ql/data/config/config.sh ] && . /ql/data/config/config.sh
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
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
