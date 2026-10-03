"""
Stock Web Dashboard - Apple Cupertino Pro Edition
Quant Signal Engine & Security Hardened Version (Fast & Safe for 512MB RAM)
"""

import gc
import io
import json
import os
import re
import secrets
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime

import numpy as np
import pandas as pd
import yfinance as yf
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE_US = os.path.join(BASE_DIR, "watchlist_config.json")
HOLDINGS_FILE_US = os.path.join(BASE_DIR, "holdings.json")
CASH_FILE_US = os.path.join(BASE_DIR, "cash_us.json")
TRADES_FILE_US = os.path.join(BASE_DIR, "trades_history.json")

CONFIG_FILE_TH = os.path.join(BASE_DIR, "watchlist_config_th.json")
HOLDINGS_FILE_TH = os.path.join(BASE_DIR, "holdings_th.json")
CASH_FILE_TH = os.path.join(BASE_DIR, "cash_th.json")
TRADES_FILE_TH = os.path.join(BASE_DIR, "trades_history_th.json")

NOTES_FILE = os.path.join(BASE_DIR, "ticker_notes.json")
CUSTOM_ALERTS_FILE = os.path.join(BASE_DIR, "custom_alerts.json")
STATE_FILE = os.path.join(BASE_DIR, "alert_state.json")
ALERT_SETTINGS_FILE = os.path.join(BASE_DIR, "alert_settings.json")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8941973568:AAFeyu4HWmmUAB6JdkhNHNvNndE4j-7OLGs")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "1340046064")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
MAX_IMPORT_BYTES = 2 * 1024 * 1024
TICKER_RE = re.compile(r"^[A-Z0-9.^-]{1,20}$")

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "ไม่พบคีย์ TELEGRAM_BOT_TOKEN หรือ TELEGRAM_CHAT_ID"
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = urllib.parse.urlencode({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            res_body = response.read().decode("utf-8")
            res_json = json.loads(res_body)
            if res_json.get("ok"):
                return True, "ส่งสำเร็จ"
            return False, res_json.get("description", "Telegram Error")
    except Exception as e:
        return False, f"Connection Error: {str(e)}"

DEFAULT_TICKERS_US = [
    "NVDA", "MELI", "NOW", "ORCL", "CEG", "TSLA", "XE", "JEPQ", "CLS", "BRUN",
    "SOFI", "PLTR", "MU", "SMCI", "APP", "ONON", "CRWV", "ASTS", "RKLB", "BE"
]

DEFAULT_TICKERS_TH = [
    "DELTA.BK", "CPALL.BK", "PTT.BK", "AOT.BK", "KBANK.BK", "BDMS.BK", "ADVANC.BK", "GULF.BK", "SCB.BK", "TRUE.BK"
]

DEFAULT_SETTINGS = {
    "check_interval_seconds": 60,
    "lookback_days": 300,
    "proximity_percent": 0.5,
    "alert_cooldown_minutes": 120,
}

TIMEFRAME_MAP = {
    "1D": ("1d", "5m"),
    "1W": ("5d", "15m"),
    "1M": ("1mo", "1d"),
    "3M": ("3mo", "1d"),
    "6M": ("6mo", "1d"),
    "1Y": ("1y", "1d"),
}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=FLASK_SECRET_KEY or secrets.token_urlsafe(32),
    MAX_CONTENT_LENGTH=MAX_IMPORT_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
)

persistence_lock = threading.RLock()
worker_start_lock = threading.Lock()
worker_started = False

def api_error(message, status=400):
    return jsonify({"error": message}), status

def require_market(value):
    market = str(value or "US").upper()
    if market not in {"US", "TH"}:
        raise ValueError("market must be US or TH")
    return market

def valid_ticker(symbol, market="US"):
    symbol = normalize_ticker(symbol, market)
    return bool(TICKER_RE.fullmatch(symbol)) and (market != "TH" or symbol.endswith(".BK"))

@app.before_request
def require_dashboard_login():
    if request.endpoint in {"login", "static"}:
        return None
    if not DASHBOARD_PASSWORD:
        return api_error("Dashboard access is not configured. Set DASHBOARD_PASSWORD and FLASK_SECRET_KEY.", 503)
    if not FLASK_SECRET_KEY:
        return api_error("Dashboard access is not configured. Set FLASK_SECRET_KEY.", 503)
    if not session.get("dashboard_authenticated"):
        if request.path.startswith("/api/"):
            return api_error("Authentication required", 401)
        return redirect(url_for("login", next=request.full_path))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            return api_error("Invalid request origin", 403)
    ensure_background_worker()

def ensure_background_worker():
    global worker_started
    if worker_started:
        return
    with worker_start_lock:
        if not worker_started:
            threading.Thread(target=background_loop, daemon=True, name="alert-worker").start()
            worker_started = True

@app.errorhandler(413)
def import_too_large(_error):
    return api_error("ไฟล์นำเข้ามีขนาดใหญ่เกินไป", 413)

@app.route("/login", methods=["GET", "POST"])
def login():
    if not DASHBOARD_PASSWORD or not FLASK_SECRET_KEY:
        return "Set DASHBOARD_PASSWORD and FLASK_SECRET_KEY in Render Environment Settings.", 503
    if request.method == "POST":
        password = request.form.get("password", "")
        if secrets.compare_digest(password, DASHBOARD_PASSWORD):
            session.clear()
            session["dashboard_authenticated"] = True
            target = request.args.get("next", "/")
            return redirect(target if target.startswith("/") and not target.startswith("//") else "/")
        return render_template("login.html", error="รหัสผ่านไม่ถูกต้อง"), 401
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

def load_json_file(path, default=None):
    if default is None:
        default = {}
    if os.path.exists(path):
        try:
            with persistence_lock, open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return default
    return default

def save_json_file(path, data):
    directory = os.path.dirname(path)
    with persistence_lock:
        fd, temp_path = tempfile.mkstemp(prefix=".write-", suffix=".json", dir=directory, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, allow_nan=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

def read_import_json(upload):
    raw = upload.read(MAX_IMPORT_BYTES + 1)
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("ไฟล์นำเข้ามีขนาดใหญ่เกินไป")
    try:
        decoded = raw.decode("utf-8")
        data = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ไฟล์ต้องเป็น JSON UTF-8 ที่ถูกต้อง") from exc
    if not isinstance(data, dict):
        raise ValueError("โครงสร้างไฟล์ไม่ถูกต้อง")
    return data

def validate_alerts(data):
    if not isinstance(data, dict) or len(data) > 500:
        raise ValueError("โครงสร้างรายการเป้าหมายไม่ถูกต้อง")
    clean = {}
    for key, entries in data.items():
        if not isinstance(key, str) or not isinstance(entries, list) or len(entries) > 100:
            raise ValueError("โครงสร้างรายการเป้าหมายไม่ถูกต้อง")
        market, sep, raw_ticker = key.partition("_")
        market = require_market(market)
        if not sep or not valid_ticker(raw_ticker, market):
            raise ValueError("พบสัญลักษณ์หุ้นไม่ถูกต้อง")
        normalized_key = f"{market}_{normalize_ticker(raw_ticker, market).replace('.BK', '')}"
        clean[normalized_key] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("รายการเป้าหมายไม่ถูกต้อง")
            try:
                price = float(entry.get("target_price"))
            except (TypeError, ValueError):
                raise ValueError("ราคาเป้าหมายไม่ถูกต้อง")
            condition = entry.get("condition")
            if not np.isfinite(price) or price <= 0 or condition not in {"gte", "lte"}:
                raise ValueError("รายการเป้าหมายไม่ถูกต้อง")
            clean[normalized_key].append({
                "target_price": round(price, 4), "condition": condition,
                "status": "triggered" if entry.get("status") == "triggered" else "pending",
                "created_at": str(entry.get("created_at", ""))[:32],
                "triggered_at": str(entry.get("triggered_at", ""))[:32] or None,
                "triggered_price": entry.get("triggered_price") if entry.get("status") == "triggered" else None,
            })
    return clean

def validate_backup(content):
    allowed = {"holdings_us", "holdings_th", "cash_us", "cash_th", "trades_us", "trades_th", "watchlist_us", "watchlist_th", "custom_alerts", "notes", "alert_settings"}
    if not set(content).intersection(allowed):
        raise ValueError("ไม่พบข้อมูลสำรองที่รองรับ")
    for market, key in (("US", "holdings_us"), ("TH", "holdings_th")):
        if key in content:
            if not isinstance(content[key], dict) or len(content[key]) > 500:
                raise ValueError("ข้อมูลพอร์ตไม่ถูกต้อง")
            for ticker, holding in content[key].items():
                if not valid_ticker(ticker, market) or not isinstance(holding, dict):
                    raise ValueError("ข้อมูลพอร์ตไม่ถูกต้อง")
                q, p = float(holding.get("quantity", 0)), float(holding.get("buy_price", 0))
                if not np.isfinite(q) or not np.isfinite(p) or q <= 0 or p <= 0:
                    raise ValueError("ข้อมูลพอร์ตไม่ถูกต้อง")
        cash_key = f"cash_{market.lower()}"
        if cash_key in content:
            cash = float(content[cash_key].get("cash", 0)) if isinstance(content[cash_key], dict) else -1
            if not np.isfinite(cash) or cash < 0:
                raise ValueError("ข้อมูลเงินสดไม่ถูกต้อง")
        watchlist_key = f"watchlist_{market.lower()}"
        if watchlist_key in content:
            config = content[watchlist_key]
            if not isinstance(config, dict) or not isinstance(config.get("tickers"), list) or len(config["tickers"]) > 200:
                raise ValueError("ข้อมูลรายการหุ้นไม่ถูกต้อง")
            if not all(isinstance(t, str) and valid_ticker(t, market) for t in config["tickers"]):
                raise ValueError("ข้อมูลรายการหุ้นไม่ถูกต้อง")
            settings = config.get("settings", {})
            if settings and not isinstance(settings, dict):
                raise ValueError("การตั้งค่าไม่ถูกต้อง")
        trades_key = f"trades_{market.lower()}"
        if trades_key in content and (not isinstance(content[trades_key], list) or len(content[trades_key]) > 5000):
            raise ValueError("ประวัติการซื้อขายไม่ถูกต้อง")
    if "custom_alerts" in content:
        content["custom_alerts"] = validate_alerts(content["custom_alerts"])
    if "notes" in content and (not isinstance(content["notes"], dict) or len(content["notes"]) > 1000):
        raise ValueError("บันทึกหุ้นไม่ถูกต้อง")
    if "alert_settings" in content:
        settings = content["alert_settings"]
        if not isinstance(settings, dict) or any(key not in {"US", "TH", "enabled"} for key in settings):
            raise ValueError("การตั้งค่าการแจ้งเตือนไม่ถูกต้อง")
    return {key: content[key] for key in allowed if key in content}

def get_market_files(market="US"):
    market = str(market).upper()
    if market == "TH":
        return CONFIG_FILE_TH, HOLDINGS_FILE_TH, CASH_FILE_TH, TRADES_FILE_TH, DEFAULT_TICKERS_TH
    return CONFIG_FILE_US, HOLDINGS_FILE_US, CASH_FILE_US, TRADES_FILE_US, DEFAULT_TICKERS_US

def load_config(market="US"):
    cfg_file, _, _, _, def_tickers = get_market_files(market)
    if os.path.exists(cfg_file):
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                if "settings" not in cfg:
                    cfg["settings"] = DEFAULT_SETTINGS.copy()
                else:
                    # ผสานเฉพาะ key ที่ยังไม่มี เพื่อไม่ให้เขียนทับค่าที่ตั้งไว้เดิม
                    for k, v in DEFAULT_SETTINGS.items():
                        if k not in cfg["settings"]:
                            cfg["settings"][k] = v
                return cfg
        except Exception:
            pass
    config = {"tickers": list(def_tickers), "settings": DEFAULT_SETTINGS.copy()}
    save_config(config, market)
    return config

def save_config(config, market="US"):
    cfg_file, _, _, _, _ = get_market_files(market)
    save_json_file(cfg_file, config)

def load_holdings(market="US"):
    _, hold_file, _, _, _ = get_market_files(market)
    return load_json_file(hold_file, {})

def save_holdings(holdings_data, market="US"):
    _, hold_file, _, _, _ = get_market_files(market)
    save_json_file(hold_file, holdings_data)

def load_cash(market="US"):
    _, _, cash_file, _, _ = get_market_files(market)
    data = load_json_file(cash_file, {"cash": 0.0})
    return float(data.get("cash", 0.0))

def save_cash(amount, market="US"):
    _, _, cash_file, _, _ = get_market_files(market)
    save_json_file(cash_file, {"cash": float(amount)})

def load_trades(market="US"):
    _, _, _, trade_file, _ = get_market_files(market)
    return load_json_file(trade_file, [])

def save_trades(trades_data, market="US"):
    _, _, _, trade_file, _ = get_market_files(market)
    save_json_file(trade_file, trades_data)

def is_alerts_enabled(market="US"):
    market = str(market).upper()
    data = load_json_file(ALERT_SETTINGS_FILE, {"US": True, "TH": True})
    return bool(data.get(market, True))

def set_alerts_enabled(market, enabled):
    market = str(market).upper()
    data = load_json_file(ALERT_SETTINGS_FILE, {"US": True, "TH": True})
    data[market] = bool(enabled)
    save_json_file(ALERT_SETTINGS_FILE, data)

watchlist_cache = {}
market_pulse_cache = {"US": {}, "TH": {}, "timestamp": 0}
cache_lock = threading.Lock()
history_cache = {}
HISTORY_TTL_SECONDS = 120
alert_state = load_json_file(STATE_FILE, {})
custom_alerts = load_json_file(CUSTOM_ALERTS_FILE, {})
ticker_notes = load_json_file(NOTES_FILE, {})

def normalize_ticker(symbol, market="US"):
    sym = str(symbol).strip().upper()
    if market == "TH" and not sym.endswith(".BK"):
        sym += ".BK"
    return sym

def flatten_columns(df):
    if isinstance(df.columns, pd.MultiIndex):
        df.columns = df.columns.get_level_values(0)
    return df

def download_history(ticker, period, interval="1d", ttl=HISTORY_TTL_SECONDS):
    key = (ticker, period, interval)
    now = time.monotonic()
    with cache_lock:
        cached = history_cache.get(key)
        if cached and now - cached[0] < ttl:
            return cached[1].copy()
    last_error = None
    for attempt in range(3):
        try:
            frame = yf.download(ticker, period=period, interval=interval, progress=False, threads=False)
            frame = flatten_columns(frame)
            if not frame.empty:
                with cache_lock:
                    history_cache[key] = (time.monotonic(), frame.copy())
                    if len(history_cache) > 160:
                        oldest = min(history_cache, key=lambda k: history_cache[k][0])
                        history_cache.pop(oldest, None)
                return frame
            last_error = RuntimeError("Yahoo Finance returned no data")
        except Exception as exc:
            last_error = exc
        time.sleep(0.5 * (2 ** attempt))
    raise RuntimeError("Market data is temporarily unavailable") from last_error

def compute_atr(df, period=14):
    if len(df) < period + 1:
        return 0.0
    high = df["High"]
    low = df["Low"]
    close = df["Close"]
    prev_close = close.shift(1)
    
    tr1 = high - low
    tr2 = (high - prev_close).abs()
    tr3 = (low - prev_close).abs()
    tr = pd.concat([tr1, tr2, tr3], axis=1).max(axis=1)
    atr = tr.ewm(alpha=1 / period, adjust=False, min_periods=period).mean()
    val = atr.dropna().iloc[-1] if not atr.dropna().empty else (high.iloc[-1] - low.iloc[-1])
    return round(float(val), 2)

def compute_support_resistance(df):
    highs = df["High"]
    lows = df["Low"]
    swing_highs = highs[(highs.shift(1) < highs) & (highs.shift(-1) < highs)].dropna()
    swing_lows = lows[(lows.shift(1) > lows) & (lows.shift(-1) > lows)].dropna()
    
    unique_res = sorted(list(set(np.round(swing_highs.tail(6).values, 2))))
    unique_sup = sorted(list(set(np.round(swing_lows.tail(6).values, 2))), reverse=True)
    
    resistance_levels = [float(r) for r in unique_res[-4:]] if unique_res else [round(float(highs.max()), 2)]
    support_levels = [float(s) for s in unique_sup[:4]] if unique_sup else [round(float(lows.min()), 2)]
    
    mean_resistance = round(float(np.mean(resistance_levels)), 2)
    mean_support = round(float(np.mean(support_levels)), 2)
    return mean_support, mean_resistance, support_levels, resistance_levels

def compute_fibonacci_levels(df):
    high = float(df["High"].max())
    low = float(df["Low"].min())
    diff = high - low
    if diff <= 0:
        return {}
    return {
        "0.0": round(high, 2),
        "0.236": round(high - 0.236 * diff, 2),
        "0.382": round(high - 0.382 * diff, 2),
        "0.500": round(high - 0.500 * diff, 2),
        "0.618": round(high - 0.618 * diff, 2),
        "0.786": round(high - 0.786 * diff, 2),
        "1.0": round(low, 2),
    }

def compute_volume_profile(df, bins=10):
    if df.empty or "Volume" not in df.columns:
        return None
    try:
        price_min = df["Low"].min()
        price_max = df["High"].max()
        if price_max <= price_min:
            return None

        bin_edges = np.linspace(price_min, price_max, bins + 1)
        vol_profile = np.zeros(bins)

        for _, row in df.iterrows():
            avg_p = (row["High"] + row["Low"] + row["Close"]) / 3.0
            v = row["Volume"]
            bin_idx = np.digitize(avg_p, bin_edges) - 1
            if 0 <= bin_idx < bins:
                vol_profile[bin_idx] += v

        poc_idx = np.argmax(vol_profile)
        return round(float((bin_edges[poc_idx] + bin_edges[poc_idx + 1]) / 2.0), 2)
    except Exception:
        return None

def compute_trailing_stop(df, holding_info, atr_multiple=2.0):
    if not holding_info or not holding_info.get("buy_price"):
        return None
    try:
        buy_price = float(holding_info["buy_price"])
        recent_high = float(df["High"].tail(22).max())
        atr = compute_atr(df)
        if atr <= 0:
            return None
        high_water_mark = max(buy_price, recent_high)
        return round(max(0.01, high_water_mark - atr_multiple * atr), 2)
    except Exception:
        return None

def compute_indicators(df):
    close = df["Close"]
    sma20 = close.rolling(20).mean()
    sma50 = close.rolling(50).mean()
    ema200 = close.ewm(span=200, adjust=False, min_periods=200).mean()

    delta = close.diff()
    gain = delta.clip(lower=0)
    loss = -delta.clip(upper=0)
    avg_gain = gain.ewm(alpha=1 / 14, adjust=False).mean()
    avg_loss = loss.ewm(alpha=1 / 14, adjust=False).mean()
    rs = avg_gain / avg_loss.replace(0, np.nan)
    rsi = 100 - (100 / (1 + rs))

    ema12 = close.ewm(span=12, adjust=False).mean()
    ema26 = close.ewm(span=26, adjust=False).mean()
    macd = ema12 - ema26
    macd_signal = macd.ewm(span=9, adjust=False).mean()
    macd_hist = macd - macd_signal
    return sma20, sma50, ema200, rsi, macd, macd_signal, macd_hist

def detect_bullish_divergence(closes, rsis, window=14):
    if len(closes) < window or len(rsis) < window:
        return False
    c_tail = closes[-window:]
    r_tail = rsis[-window:]
    if pd.isna(r_tail).any() or pd.isna(c_tail).any():
        return False
    cur_c = c_tail[-1]
    min_c = np.min(c_tail)
    cur_r = r_tail[-1]
    min_r = np.min(r_tail)
    if cur_c <= min_c * 1.01 and cur_r > (min_r + 3.0) and cur_r < 45:
        return True
    return False

def fetch_watchlist_item(ticker, settings, holdings_snapshot):
    lookback_days = max(300, min(int(settings.get("lookback_days", 300)), 730))
    df = download_history(ticker, period=f"{lookback_days}d", interval="1d")
    if df.empty or len(df) < 15:
        return None
    df = flatten_columns(df)

    auto_sup, auto_res, sup_levels, res_levels = compute_support_resistance(df)
    sma20, sma50, ema200, rsi_series, _, _, _ = compute_indicators(df)
    atr = compute_atr(df, period=14)
    poc = compute_volume_profile(df)
    fibo = compute_fibonacci_levels(df)

    closes = df["Close"]
    current = float(closes.iloc[-1])
    prev = float(closes.iloc[-2]) if len(closes) > 1 else current
    change_pct = ((current - prev) / prev) * 100 if prev else 0.0

    support = auto_sup
    resistance = auto_res

    latest_rsi = round(float(rsi_series.dropna().iloc[-1]), 1) if not rsi_series.dropna().empty else None
    
    golden_cross = False
    valid_sma = sma20.dropna().index.intersection(sma50.dropna().index)
    if len(valid_sma) >= 2:
        last_idx = valid_sma[-1]
        prev_idx = valid_sma[-2]
        if sma20.loc[last_idx] >= sma50.loc[last_idx] and sma20.loc[prev_idx] <= sma50.loc[prev_idx]:
            golden_cross = True

    vol_ratio = 1.0
    vol_spike = False
    if "Volume" in df.columns:
        vol_ma20 = df["Volume"].rolling(window=20).mean()
        cur_v = float(df["Volume"].iloc[-1])
        avg_v = float(vol_ma20.iloc[-1]) if not pd.isna(vol_ma20.iloc[-1]) else 0
        if avg_v > 0:
            vol_ratio = round(cur_v / avg_v, 1)
            if cur_v >= (avg_v * 1.8):
                vol_spike = True

    rsi_bull_div = detect_bullish_divergence(closes.values, rsi_series.values)

    latest_ema200 = float(ema200.dropna().iloc[-1]) if not ema200.dropna().empty else current
    prev_ema200 = float(ema200.dropna().iloc[-5]) if len(ema200.dropna()) >= 5 else latest_ema200
    ema_slope_up = (current >= latest_ema200) and (latest_ema200 >= prev_ema200 * 0.999)

    poc_val = poc if poc else support
    poc_dist_pct = abs(current - poc_val) / poc_val * 100 if poc_val else 10.0
    near_poc = (poc_dist_pct <= 2.2) or (current <= support * 1.025)

    rsi_cooldown = (latest_rsi is not None and 35.0 <= latest_rsi <= 58.0)

    quant_pass_count = sum([ema_slope_up, near_poc, rsi_cooldown, vol_spike])
    is_quant_triggered = quant_pass_count == 4

    proximity = settings.get("proximity_percent", 0.5)
    if current <= support * (1 + proximity / 100):
        status = "support"
    elif current >= resistance * (1 - proximity / 100):
        status = "resistance"
    else:
        status = "normal"

    pnl = None
    holding = holdings_snapshot.get(ticker)
    trailing_stop = None
    if holding and holding.get("quantity"):
        qty = holding["quantity"]
        buy_price = holding["buy_price"]
        pnl_amount = (current - buy_price) * qty
        pnl_pct = ((current - buy_price) / buy_price) * 100 if buy_price else 0.0
        pnl = {
            "quantity": qty,
            "buy_price": buy_price,
            "amount": round(pnl_amount, 2),
            "percent": round(pnl_pct, 2),
        }
        trailing_stop = compute_trailing_stop(df, holding)

    return {
        "ticker": ticker,
        "price": round(current, 2),
        "change_pct": round(change_pct, 2),
        "support": support,
        "resistance": resistance,
        "support_levels": sup_levels,
        "resistance_levels": res_levels,
        "is_custom": False,
        "status": status,
        "rsi": latest_rsi,
        "golden_cross": golden_cross,
        "is_confluence": False,
        "vol_spike": vol_spike,
        "vol_ratio": vol_ratio,
        "rsi_bull_div": rsi_bull_div,
        "earnings_date": None,
        "div_yield": None,
        "trailing_stop": trailing_stop,
        "pnl": pnl,
        "atr": atr,
        "poc": poc_val,
        "fibo_0": fibo.get("0.0", resistance),
        "quant_triggered": is_quant_triggered,
        "quant_pass_count": quant_pass_count,
        "quant_factors": {
            "ema_slope": ema_slope_up,
            "near_poc": near_poc,
            "rsi_cooldown": rsi_cooldown,
            "vol_spike": vol_spike
        }
    }

def check_all_custom_alerts():
    global custom_alerts
    alerts_data = load_json_file(CUSTOM_ALERTS_FILE, {})
    if not alerts_data:
        return

    updated = False
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    for key in list(alerts_data.keys()):
        parts = key.split("_", 1)
        if len(parts) != 2:
            continue
        market, ticker = parts[0], parts[1]

        if not is_alerts_enabled(market):
            continue

        sym_download = normalize_ticker(ticker, market)
        try:
            df_quick = download_history(sym_download, period="5d", interval="1d")
            current_price = float(df_quick["Close"].iloc[-1]) if not df_quick.empty else None
            if current_price is None:
                continue
            current_price = round(float(current_price), 2)
        except Exception:
            continue

        sym = "฿" if market == "TH" else "$"
        flag = "🇹🇭" if market == "TH" else "🇺🇸"
        display_ticker = ticker.replace(".BK", "")

        for entry in alerts_data[key]:
            if entry.get("status") == "triggered":
                continue

            target = float(entry.get("target_price", 0))
            cond = entry.get("condition", "gte")
            triggered = False

            if cond == "gte" and current_price >= target:
                triggered = True
                msg = (
                    f"🎯 <b>[เป้าหมายราคา] {flag} {display_ticker}</b>\n"
                    f"━━━━━━━━━━━━━━━\n"
                    f"📈 ราคาขึ้นแตะเป้าหมาย: <b>{sym}{current_price:.2f}</b> (ตั้งไว้ ≥ {sym}{target:.2f})\n"
                    f"⏰ เวลา: {datetime.now().strftime('%H:%M:%S')}"
                )
                send_telegram_alert(msg)
            elif cond == "lte" and current_price <= target:
                triggered = True
                msg = (
                    f"🎯 <b>[จุดเฝ้าระวัง] {flag} {display_ticker}</b>\n"
                    f"━━━━━━━━━━━━━━━\n"
                    f"📉 ราคาลงมาแตะเป้าหมาย: <b>{sym}{current_price:.2f}</b> (ตั้งไว้ ≤ {sym}{target:.2f})\n"
                    f"⏰ เวลา: {datetime.now().strftime('%H:%M:%S')}"
                )
                send_telegram_alert(msg)

            if triggered:
                entry["status"] = "triggered"
                entry["triggered_at"] = now_str
                entry["triggered_price"] = current_price
                updated = True

    if updated:
        save_json_file(CUSTOM_ALERTS_FILE, alerts_data)
        custom_alerts = alerts_data

def send_quant_signal(ticker, market, item):
    sym = "฿" if market == "TH" else "$"
    display_ticker = ticker.replace(".BK", "")
    current_p = item["price"]
    atr_val = item.get("atr", current_p * 0.02)
    
    entry_low = round(current_p * 0.996, 2)
    entry_high = round(current_p * 1.004, 2)

    stop_p = round(max(0.01, current_p - (2.0 * atr_val)), 2)
    risk_per_share = current_p - stop_p
    stop_pct = round(((stop_p - current_p) / current_p) * 100, 1)

    tp1 = round(item.get("fibo_0") or item.get("resistance") or (current_p + (2.0 * risk_per_share)), 2)
    if tp1 <= current_p:
        tp1 = round(current_p + (2.2 * risk_per_share), 2)
    tp1_pct = round(((tp1 - current_p) / current_p) * 100, 1)

    reward_per_share = tp1 - current_p
    rrr = round(reward_per_share / risk_per_share, 2) if risk_per_share > 0 else 2.0

    base_cap = 100000 if market == "TH" else 10000
    max_risk_cash = base_cap * 0.02
    recommended_shares = int(max_risk_cash / risk_per_share) if risk_per_share > 0 else 1
    total_alloc = round(recommended_shares * current_p, 2)

    factors = item.get("quant_factors", {})
    chk1 = "✓" if factors.get("ema_slope") else "✕"
    chk2 = "✓" if factors.get("near_poc") else "✕"
    chk3 = "✓" if factors.get("rsi_cooldown") else "✕"
    chk4 = "✓" if factors.get("vol_spike") else "✕"
    poc_str = f"{sym}{item.get('poc', current_p):.2f}"
    rsi_str = f"{item.get('rsi', 45.0)}"
    vol_str = f"{item.get('vol_ratio', 2.0)}x"

    msg = (
        f"⚡ <b>[QUANT SIGNAL TRIGGERED] 🟢 LONG</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📌 Symbol: <b>{display_ticker} ({market})</b>\n"
        f"⏱ Time: <b>{datetime.now().strftime('%H:%M:%S')}</b>\n"
        f"📊 Setup: <b>Trend Pullback + Volume Spike</b>\n\n"
        f"💰 <b>Execution Parameters:</b>\n"
        f"• Entry Zone: {sym}{entry_low:.2f} - {sym}{entry_high:.2f}\n"
        f"• Dynamic Stop (2 ATR): {sym}{stop_p:.2f} ({stop_pct:.1f}%)\n"
        f"• Take Profit 1 (Fibo 0.0): {sym}{tp1:.2f} (+{tp1_pct:.1f}%)\n"
        f"• Risk/Reward Ratio: <b>1 : {rrr:.2f}</b>\n\n"
        f"🛡 <b>Position Sizing Guide</b> (พอร์ต {sym}{base_cap:,} | เสี่ยง 2%):\n"
        f"• Max Risk Amount: {sym}{max_risk_cash:,.0f}\n"
        f"• Recommended Size: <b>{recommended_shares:,} หุ้น</b> (ใช้เงิน ~{sym}{total_alloc:,.0f})\n\n"
        f"📈 <b>Quant Checklist Passed:</b>\n"
        f"[{chk1}] EMA 200 Uptrend Slope\n"
        f"[{chk2}] Pullback to POC ({poc_str})\n"
        f"[{chk3}] RSI {rsi_str} (Cooldown)\n"
        f"[{chk4}] Vol Spike {vol_str}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━"
    )
    return send_telegram_alert(msg)

def maybe_alert(ticker, status, item, settings):
    ticker_market = "TH" if ticker.endswith(".BK") else "US"
    if not is_alerts_enabled(ticker_market):
        return

    cooldown = settings.get("alert_cooldown_minutes", 120)

    if item.get("quant_triggered"):
        q_key = f"{ticker}_QUANT_LONG"
        last_q = alert_state.get(q_key)
        can_send_q = True
        if last_q:
            try:
                el = (datetime.now() - datetime.fromisoformat(last_q)).total_seconds() / 60
                if el < cooldown:
                    can_send_q = False
            except Exception:
                pass
        if can_send_q:
            alert_state[q_key] = datetime.now().isoformat()
            save_json_file(STATE_FILE, alert_state)
            send_quant_signal(ticker, ticker_market, item)
            return

    if status == "normal" and not item.get("vol_spike"):
        return

    key = f"{ticker}_{status}"
    last = alert_state.get(key)
    if last:
        try:
            elapsed = (datetime.now() - datetime.fromisoformat(last)).total_seconds() / 60
            if elapsed < cooldown:
                return
        except Exception:
            pass

    alert_state[key] = datetime.now().isoformat()
    save_json_file(STATE_FILE, alert_state)

    is_th = (ticker_market == "TH")
    cur_sym = "฿" if is_th else "$"
    flag = "🇹🇭" if is_th else "🇺🇸"
    display_ticker = ticker.replace(".BK", "") if is_th else ticker
    spike_tag = f"\n🔥 <b>[Volume Spike] วอลุ่มเข้าผิดปกติ {item.get('vol_ratio', 2.0)}x!</b>" if item.get("vol_spike") else ""
    div_tag = "\n⚡ <b>[RSI Bullish Divergence] สัญญาณกลับตัว!</b>" if item.get("rsi_bull_div") else ""

    current = item["price"]
    if status == "support":
        level = item["support"]
        remaining_pct = abs((current - level) / level) * 100 if level else 0
        msg_telegram = (
            f"🟢 <b>{flag} {display_ticker} ใกล้ถึงแนวรับ!</b>{spike_tag}{div_tag}\n"
            f"━━━━━━━━━━━━━━━\n"
            f"💰 ราคาปัจจุบัน: <b>{cur_sym}{current:.2f}</b>\n"
            f"🎯 แนวรับ: <b>{cur_sym}{level:.2f}</b> (ห่าง {remaining_pct:.2f}%)\n"
            f"📊 RSI: <b>{item.get('rsi') or '—'}</b>\n"
            f"⏰ เวลา: {datetime.now().strftime('%H:%M:%S')}"
        )
    elif status == "resistance":
        level = item["resistance"]
        remaining_pct = abs((level - current) / level) * 100 if level else 0
        msg_telegram = (
            f"🔴 <b>{flag} {display_ticker} ใกล้ถึงแนวต้าน!</b>{spike_tag}\n"
            f"━━━━━━━━━━━━━━━\n"
            f"💰 ราคาปัจจุบัน: <b>{cur_sym}{current:.2f}</b>\n"
            f"🎯 แนวต้าน: <b>{cur_sym}{level:.2f}</b> (ห่าง {remaining_pct:.2f}%)\n"
            f"📊 RSI: <b>{item.get('rsi') or '—'}</b>\n"
            f"⏰ เวลา: {datetime.now().strftime('%H:%M:%S')}"
        )
    else:
        return

    send_telegram_alert(msg_telegram)

def background_loop():
    global alert_state
    alert_state = load_json_file(STATE_FILE, {})
    while True:
        try:
            check_all_custom_alerts()
            for mkt in ["US", "TH"]:
                config = load_config(mkt)
                h_data = load_holdings(mkt)
                settings = config.get("settings", DEFAULT_SETTINGS)
                for ticker in list(config.get("tickers", [])):
                    try:
                        item = fetch_watchlist_item(ticker, settings, dict(h_data))
                    except Exception:
                        item = None
                    if item:
                        with cache_lock:
                            watchlist_cache[ticker] = item
                        maybe_alert(ticker, item["status"], item, settings)
                    time.sleep(0.5)
                    gc.collect()
            save_json_file(STATE_FILE, alert_state)
        except Exception:
            pass
        time.sleep(60)

# ====================== API Routes ======================
@app.route("/api/system-status")
def api_system_status():
    mem_mb = 135.0
    try:
        import resource
        mem_bytes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        mem_mb = round(mem_bytes / 1024.0, 1)
    except Exception:
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        mem_mb = round(float(line.split()[1]) / 1024.0, 1)
                        break
        except Exception:
            mem_mb = 142.0

    percent_used = round((mem_mb / 512.0) * 100, 1)
    status_color = "🟢 ปลอดภัย" if mem_mb < 320 else "🟡 เริ่มตึง"

    return jsonify({
        "status": status_color,
        "ram_used_mb": f"{mem_mb} MB",
        "ram_limit": "512 MB",
        "usage_percent": f"{percent_used}%"
    })

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/custom-alerts/export")
def api_custom_alerts_export():
    alerts_data = load_json_file(CUSTOM_ALERTS_FILE, {})
    json_bytes = json.dumps(alerts_data, ensure_ascii=False, indent=2).encode("utf-8")
    return send_file(
        io.BytesIO(json_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"stock_alerts_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

@app.route("/api/custom-alerts/import", methods=["POST"])
def api_custom_alerts_import():
    global custom_alerts
    if "file" not in request.files:
        return jsonify({"error": "ไม่พบไฟล์สำหรับกู้คืน"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "ไม่ได้เลือกไฟล์"}), 400

    try:
        content = validate_alerts(read_import_json(file))
        save_json_file(CUSTOM_ALERTS_FILE, content)
        custom_alerts = content
        return jsonify({"ok": True, "message": "กู้คืนรายการเป้าหมายราคาสำเร็จแล้ว!"})
    except ValueError as exc:
        return api_error(str(exc))

@app.route("/api/custom-alerts/all-detailed")
def api_custom_alerts_all_detailed():
    alerts_data = load_json_file(CUSTOM_ALERTS_FILE, {})
    items = []
    
    with cache_lock:
        local_cache = dict(watchlist_cache)

    for key, alert_list in alerts_data.items():
        parts = key.split("_", 1)
        if len(parts) != 2:
            continue
        market, ticker = parts[0], parts[1]
        display_ticker = ticker.replace(".BK", "")
        sym_download = normalize_ticker(ticker, market)

        current_p = None
        if sym_download in local_cache and local_cache[sym_download].get("price"):
            current_p = local_cache[sym_download]["price"]
        else:
            try:
                hist = download_history(sym_download, period="5d", interval="1d")
                current_p = float(hist["Close"].iloc[-1]) if not hist.empty else None
                if current_p is not None and not np.isnan(current_p):
                    current_p = round(float(current_p), 2)
            except Exception:
                current_p = None

        for idx, a in enumerate(alert_list):
            items.append({
                "key": key,
                "index": idx,
                "market": market,
                "ticker": ticker,
                "display_ticker": display_ticker,
                "target_price": float(a.get("target_price", 0)),
                "condition": a.get("condition", "gte"),
                "status": a.get("status", "pending"),
                "triggered_at": a.get("triggered_at", None),
                "triggered_price": a.get("triggered_price", None),
                "current_price": current_p,
                "created_at": a.get("created_at", "")
            })

    return jsonify({"items": items})

@app.route("/api/custom-alerts/test-trigger", methods=["POST"])
def api_custom_alerts_test_trigger():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "")
    try:
        idx = int(data.get("index", 0))
    except (TypeError, ValueError):
        return api_error("ลำดับรายการไม่ถูกต้อง")

    alerts_data = load_json_file(CUSTOM_ALERTS_FILE, {})
    if key not in alerts_data or idx >= len(alerts_data[key]):
        return jsonify({"error": "ไม่พบรายการ"}), 404

    parts = key.split("_", 1)
    market, ticker = parts[0], parts[1]
    display_ticker = ticker.replace(".BK", "")
    entry = alerts_data[key][idx]
    target = entry.get("target_price")
    sym = "฿" if market == "TH" else "$"
    flag = "🇹🇭" if market == "TH" else "🇺🇸"

    msg = (
        f"🎯 <b>[ทดสอบระบบแจ้งเตือนเป้าหมาย] {flag} {display_ticker}</b>\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🔔 ข้อความทดสอบ: ราคาแตะเป้าหมาย <b>{sym}{target:.2f}</b> เรียบร้อย!\n"
        f"⏰ เวลา: {datetime.now().strftime('%H:%M:%S')}"
    )
    ok, err = send_telegram_alert(msg)
    if ok:
        entry["status"] = "triggered"
        entry["triggered_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
        save_json_file(CUSTOM_ALERTS_FILE, alerts_data)
        return jsonify({"success": True, "message": "ส่งทดสอบเข้า Telegram แล้ว"})
    return jsonify({"error": err}), 400

@app.route("/api/custom-alerts", methods=["GET", "POST", "DELETE"])
def api_custom_alerts():
    global custom_alerts
    alerts_data = load_json_file(CUSTOM_ALERTS_FILE, {})
    
    if request.method == "GET":
        raw_ticker = request.args.get("ticker", "").strip().upper()
        market = request.args.get("market", "US").upper()
        base_sym = raw_ticker.replace(".BK", "")
        
        keys = [f"{market}_{base_sym}", f"{market}_{raw_ticker}"]
        for k in keys:
            if k in alerts_data:
                return jsonify({"ticker": raw_ticker, "alerts": alerts_data[k]})
        return jsonify({"ticker": raw_ticker, "alerts": []})

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        raw_ticker = str(data.get("ticker", "")).strip().upper()
        try:
            market = require_market(data.get("market", "US"))
            target_price = float(data.get("target_price", 0))
        except (TypeError, ValueError):
            return api_error("ข้อมูลไม่ถูกต้อง")
        condition = data.get("condition", "gte")

        if not raw_ticker or not valid_ticker(raw_ticker, market) or not np.isfinite(target_price) or target_price <= 0 or condition not in {"gte", "lte"}:
            return jsonify({"error": "ข้อมูลไม่ถูกต้อง"}), 400

        base_sym = raw_ticker.replace(".BK", "")
        key = f"{market}_{base_sym}"
        if key not in alerts_data:
            alerts_data[key] = []

        alert_entry = {
            "target_price": target_price,
            "condition": condition,
            "status": "pending",
            "created_at": datetime.now().strftime("%H:%M:%S")
        }
        alerts_data[key].append(alert_entry)
        save_json_file(CUSTOM_ALERTS_FILE, alerts_data)
        custom_alerts = alerts_data
        return jsonify({"success": True, "alerts": alerts_data[key]})

    if request.method == "DELETE":
        raw_ticker = request.args.get("ticker", "").strip().upper()
        market = request.args.get("market", "US").upper()
        base_sym = raw_ticker.replace(".BK", "")
        try:
            idx = int(request.args.get("index", -1))
        except (TypeError, ValueError):
            return api_error("ลำดับรายการไม่ถูกต้อง")

        keys = [f"{market}_{base_sym}", f"{market}_{raw_ticker}"]
        matched_k = None
        for k in keys:
            if k in alerts_data:
                matched_k = k
                break

        if matched_k and 0 <= idx < len(alerts_data[matched_k]):
            alerts_data[matched_k].pop(idx)
            if not alerts_data[matched_k]:
                alerts_data.pop(matched_k, None)
            save_json_file(CUSTOM_ALERTS_FILE, alerts_data)
            custom_alerts = alerts_data
            return jsonify({"success": True})
        return jsonify({"error": "ไม่พบรายการ"}), 404

@app.route("/api/backup/export")
def api_backup_export():
    backup_data = {
        "export_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "holdings_us": load_json_file(HOLDINGS_FILE_US, {}),
        "holdings_th": load_json_file(HOLDINGS_FILE_TH, {}),
        "cash_us": load_json_file(CASH_FILE_US, {"cash": 0.0}),
        "cash_th": load_json_file(CASH_FILE_TH, {"cash": 0.0}),
        "trades_us": load_json_file(TRADES_FILE_US, []),
        "trades_th": load_json_file(TRADES_FILE_TH, []),
        "watchlist_us": load_config("US"),
        "watchlist_th": load_config("TH"),
        "custom_alerts": load_json_file(CUSTOM_ALERTS_FILE, {}),
        "notes": load_json_file(NOTES_FILE, {}),
        "alert_settings": load_json_file(ALERT_SETTINGS_FILE, {"US": True, "TH": True})
    }
    json_bytes = json.dumps(backup_data, ensure_ascii=False, indent=2).encode("utf-8")
    return send_file(
        io.BytesIO(json_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"stock_dashboard_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

@app.route("/api/backup/import", methods=["POST"])
def api_backup_import():
    if "file" not in request.files:
        return jsonify({"error": "ไม่พบไฟล์สำหรับกู้คืน"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "ไม่ได้เลือกไฟล์"}), 400

    try:
        content = validate_backup(read_import_json(file))
        targets = {
            "holdings_us": HOLDINGS_FILE_US, "holdings_th": HOLDINGS_FILE_TH,
            "cash_us": CASH_FILE_US, "cash_th": CASH_FILE_TH,
            "trades_us": TRADES_FILE_US, "trades_th": TRADES_FILE_TH,
            "watchlist_us": CONFIG_FILE_US, "watchlist_th": CONFIG_FILE_TH,
            "custom_alerts": CUSTOM_ALERTS_FILE, "notes": NOTES_FILE,
            "alert_settings": ALERT_SETTINGS_FILE,
        }
        with persistence_lock:
            for key, path in targets.items():
                if key in content:
                    save_json_file(path, content[key])

        return jsonify({"ok": True, "message": "กู้คืนข้อมูลสำเร็จแล้ว!"})
    except (ValueError, TypeError):
        return api_error("ไฟล์ Backup ไม่ถูกต้อง")

@app.route("/api/market-pulse")
def api_market_pulse():
    market = request.args.get("market", "US").upper()
    now_ts = time.time()

    if now_ts - market_pulse_cache.get("timestamp", 0) < 60 and market_pulse_cache.get(market):
        return jsonify(market_pulse_cache[market])

    indices = ["^GSPC", "^IXIC"] if market == "US" else ["^SET.BK"]
    result = []
    for idx in indices:
        try:
            df = download_history(idx, period="5d", interval="1d")
            if not df.empty:
                df = flatten_columns(df)
                closes = df["Close"]
                cur = float(closes.iloc[-1])
                prev = float(closes.iloc[-2]) if len(closes) > 1 else cur
                chg_pct = ((cur - prev) / prev) * 100 if prev else 0.0
                name = "S&P 500" if idx == "^GSPC" else "NASDAQ" if idx == "^IXIC" else "SET Index"
                result.append({
                    "name": name,
                    "price": round(cur, 2),
                    "change_pct": round(chg_pct, 2)
                })
        except Exception:
            pass

    market_pulse_cache[market] = result
    market_pulse_cache["timestamp"] = now_ts
    return jsonify(result)

@app.route("/api/notes", methods=["GET", "POST"])
def api_notes():
    global ticker_notes
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        ticker = str(data.get("ticker", "")).strip().upper()
        note = str(data.get("note", ""))[:5000]
        if ticker and valid_ticker(ticker):
            ticker_notes[ticker] = note
            save_json_file(NOTES_FILE, ticker_notes)
            return jsonify({"ok": True})
        return jsonify({"error": "ใส่ชื่อหุ้น"}), 400

    ticker = request.args.get("ticker", "").strip().upper()
    return jsonify({"note": ticker_notes.get(ticker, "")})

@app.route("/api/alert-toggle", methods=["GET", "POST"])
def api_alert_toggle():
    try:
        market = require_market(request.args.get("market", "US"))
    except ValueError:
        return api_error("ตลาดไม่ถูกต้อง")
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled") is True
        set_alerts_enabled(market, enabled)
        return jsonify({"market": market, "enabled": enabled})
    return jsonify({"market": market, "enabled": is_alerts_enabled(market)})

@app.route("/api/watchlist")
def api_watchlist():
    try:
        market = require_market(request.args.get("market", "US"))
    except ValueError:
        return api_error("ตลาดไม่ถูกต้อง")
    force_refresh = request.args.get("refresh", "0") == "1"
    config = load_config(market)
    h_data = load_holdings(market)
    settings = config.get("settings", DEFAULT_SETTINGS)

    items = []
    with cache_lock:
        cached_items = dict(watchlist_cache)

    for ticker in config.get("tickers", []):
        if not force_refresh and ticker in cached_items:
            items.append(cached_items[ticker])
        else:
            try:
                it = fetch_watchlist_item(ticker, settings, h_data)
                if it:
                    with cache_lock:
                        watchlist_cache[ticker] = it
                    items.append(it)
                else:
                    items.append({
                        "ticker": ticker, "price": 0.0, "change_pct": 0.0,
                        "support": 0.0, "resistance": 0.0, "status": "normal",
                        "pnl": None, "rsi": None, "golden_cross": False, "is_confluence": False,
                        "vol_spike": False, "rsi_bull_div": False, "earnings_date": None, "div_yield": None,
                        "loading": True
                    })
            except Exception:
                items.append({
                    "ticker": ticker, "price": 0.0, "change_pct": 0.0,
                    "support": 0.0, "resistance": 0.0, "status": "normal",
                    "pnl": None, "rsi": None, "golden_cross": False, "is_confluence": False,
                    "vol_spike": False, "rsi_bull_div": False, "earnings_date": None, "div_yield": None,
                    "loading": True
                })

    return jsonify({
        "items": items,
        "updated_at": datetime.now().strftime("%H:%M:%S")
    })

@app.route("/api/tickers", methods=["GET", "POST", "DELETE"])
def api_tickers():
    try:
        market = require_market(request.args.get("market", "US"))
    except ValueError:
        return api_error("ตลาดไม่ถูกต้อง")
    config = load_config(market)

    if request.method == "GET":
        return jsonify(config.get("tickers", []))

    data = request.get_json(silent=True) or {}
    raw_symbol = str(data.get("ticker", "")).strip()
    if not raw_symbol or not valid_ticker(raw_symbol, market):
        return jsonify({"error": "ใส่สัญลักษณ์หุ้น"}), 400

    symbol = normalize_ticker(raw_symbol, market)

    if request.method == "POST":
        if symbol not in config.get("tickers", []):
            if "tickers" not in config:
                config["tickers"] = []
            config["tickers"].append(symbol)
            save_config(config, market)
    elif request.method == "DELETE":
        if symbol in config.get("tickers", []):
            config["tickers"].remove(symbol)
            save_config(config, market)
            with cache_lock:
                watchlist_cache.pop(symbol, None)
                # ลบ cache ประวัติราคาเพื่อความสะอาด
                for k in list(history_cache.keys()):
                    if k[0] == symbol:
                        history_cache.pop(k, None)

    return jsonify(config.get("tickers", []))

@app.route("/api/holdings", methods=["GET", "POST"])
def api_holdings():
    try:
        market = require_market(request.args.get("market", "US"))
    except ValueError:
        return api_error("ตลาดไม่ถูกต้อง")
    current_holdings = load_holdings(market)

    if request.method == "GET":
        return jsonify(current_holdings)

    data = request.get_json(silent=True) or {}
    raw_symbol = str(data.get("ticker", "")).strip()
    if not raw_symbol or not valid_ticker(raw_symbol, market):
        return jsonify({"error": "ใส่สัญลักษณ์หุ้น"}), 400

    symbol = normalize_ticker(raw_symbol, market)
    quantity = data.get("quantity")
    buy_price = data.get("buy_price")

    try:
        quantity = float(quantity)
    except (TypeError, ValueError):
        return jsonify({"error": "จำนวนหุ้นไม่ถูกต้อง"}), 400

    if not np.isfinite(quantity):
        return api_error("จำนวนหุ้นไม่ถูกต้อง")
    if quantity <= 0:
        current_holdings.pop(symbol, None)
    else:
        try:
            buy_price = float(buy_price)
        except (TypeError, ValueError):
            return jsonify({"error": "ราคาทุนไม่ถูกต้อง"}), 400
        if not np.isfinite(buy_price) or buy_price <= 0:
            return api_error("ราคาทุนไม่ถูกต้อง")
        current_holdings[symbol] = {"quantity": quantity, "buy_price": buy_price}

    save_holdings(current_holdings, market)
    return jsonify(current_holdings)

@app.route("/api/cash", methods=["GET", "POST"])
def api_cash():
    try:
        market = require_market(request.args.get("market", "US"))
    except ValueError:
        return api_error("ตลาดไม่ถูกต้อง")
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        try:
            amount = float(data.get("cash", 0.0))
            if not np.isfinite(amount) or amount < 0:
                return api_error("จำนวนเงินสดไม่ถูกต้อง")
            save_cash(amount, market)
            return jsonify({"ok": True, "cash": amount})
        except (TypeError, ValueError):
            return jsonify({"error": "จำนวนเงินสดไม่ถูกต้อง"}), 400
    
    return jsonify({"cash": load_cash(market)})

@app.route("/api/portfolio-summary")
def api_portfolio_summary():
    try:
        market = require_market(request.args.get("market", "US"))
    except ValueError:
        return api_error("ตลาดไม่ถูกต้อง")
    current_holdings = load_holdings(market)
    cash_amount = load_cash(market)

    total_cost = 0.0
    total_value = 0.0
    items = []

    with cache_lock:
        cache_copy = dict(watchlist_cache)

    for ticker, h in current_holdings.items():
        qty = float(h.get("quantity", 0))
        buy_price = float(h.get("buy_price", 0))
        cost = qty * buy_price

        change_pct = 0.0
        cached_item = cache_copy.get(ticker)
        if cached_item and cached_item.get("price"):
            current_price = cached_item["price"]
            change_pct = cached_item.get("change_pct", 0.0)
        else:
            try:
                stock_data = download_history(ticker, period="5d", interval="1d")
                if not stock_data.empty:
                    stock_data = flatten_columns(stock_data)
                    closes = stock_data["Close"]
                    current_price = round(float(closes.iloc[-1]), 2)
                    prev_close = float(closes.iloc[-2]) if len(closes) > 1 else current_price
                    change_pct = round(((current_price - prev_close) / prev_close) * 100, 2) if prev_close else 0.0
                else:
                    current_price = buy_price
            except Exception:
                current_price = buy_price

        market_value = qty * current_price
        pnl = market_value - cost
        pnl_pct = ((current_price - buy_price) / buy_price * 100) if buy_price else 0.0

        total_cost += cost
        total_value += market_value

        items.append({
            "ticker": ticker,
            "quantity": qty,
            "buy_price": buy_price,
            "current_price": current_price,
            "change_pct": change_pct,
            "cost": round(cost, 2),
            "market_value": round(market_value, 2),
            "pnl": round(pnl, 2),
            "pnl_pct": round(pnl_pct, 2)
        })

    net_worth = total_value + cash_amount
    for item in items:
        item["weight_pct"] = round((item["market_value"] / net_worth * 100), 2) if net_worth > 0 else 0.0

    total_pnl = total_value - total_cost
    total_pnl_pct = ((total_value - total_cost) / total_cost * 100) if total_cost > 0 else 0.0

    return jsonify({
        "total_cost": round(total_cost, 2),
        "total_value": round(total_value, 2),
        "cash": round(cash_amount, 2),
        "net_worth": round(net_worth, 2),
        "total_pnl": round(total_pnl, 2),
        "total_pnl_pct": round(total_pnl_pct, 2),
        "holdings": items
    })

@app.route("/api/trades", methods=["GET", "POST", "DELETE"])
def api_trades():
    try:
        market = require_market(request.args.get("market", "US"))
    except ValueError:
        return api_error("ตลาดไม่ถูกต้อง")
    trades = load_trades(market)

    if request.method == "GET":
        total_realized_pnl = sum(t.get("realized_pnl", 0.0) for t in trades)
        total_wins = sum(1 for t in trades if t.get("realized_pnl", 0.0) > 0)
        total_losses = sum(1 for t in trades if t.get("realized_pnl", 0.0) < 0)
        win_rate = (total_wins / len(trades) * 100) if trades else 0.0

        gross_profit = sum(t.get("realized_pnl", 0.0) for t in trades if t.get("realized_pnl", 0.0) > 0)
        gross_loss = abs(sum(t.get("realized_pnl", 0.0) for t in trades if t.get("realized_pnl", 0.0) < 0))
        profit_factor = (gross_profit / gross_loss) if gross_loss > 0 else (99.9 if gross_profit > 0 else 0.0)

        return jsonify({
            "trades": trades,
            "total_realized_pnl": round(total_realized_pnl, 2),
            "win_rate": round(win_rate, 1),
            "profit_factor": round(profit_factor, 2),
            "wins": total_wins,
            "losses": total_losses
        })

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        raw_symbol = str(data.get("ticker", "")).strip()
        if not raw_symbol or not valid_ticker(raw_symbol, market):
            return jsonify({"error": "ใส่สัญลักษณ์หุ้น"}), 400

        symbol = normalize_ticker(raw_symbol, market)
        try:
            qty = float(data.get("quantity", 0))
            sell_price = float(data.get("sell_price", 0))
        except (TypeError, ValueError):
            return api_error("ข้อมูลการขายไม่ถูกต้อง")

        if not np.isfinite(qty) or not np.isfinite(sell_price) or qty <= 0 or sell_price <= 0:
            return jsonify({"error": "ข้อมูลการขายไม่ถูกต้อง"}), 400

        current_holdings = load_holdings(market)
        holding = current_holdings.get(symbol)
        if not holding:
            return api_error("ไม่พบหุ้นในพอร์ต", 404)
        available_qty = float(holding.get("quantity", 0))
        buy_price = float(holding.get("buy_price", 0))
        if qty > available_qty + 1e-9 or buy_price <= 0:
            return api_error("จำนวนหุ้นที่ขายเกินพอร์ต", 400)

        realized_pnl = (sell_price - buy_price) * qty
        realized_pct = ((sell_price - buy_price) / buy_price * 100) if buy_price else 0.0

        trade_item = {
            "id": int(time.time() * 1000),
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "ticker": symbol,
            "quantity": qty,
            "buy_price": round(buy_price, 2),
            "sell_price": round(sell_price, 2),
            "total_sold_value": round(qty * sell_price, 2),
            "realized_pnl": round(realized_pnl, 2),
            "realized_pct": round(realized_pct, 2)
        }

        with persistence_lock:
            trades.insert(0, trade_item)
            save_trades(trades, market)
            remaining = available_qty - qty
            if remaining <= 1e-9:
                current_holdings.pop(symbol, None)
            else:
                current_holdings[symbol] = {"quantity": remaining, "buy_price": buy_price}
            save_holdings(current_holdings, market)
            save_cash(load_cash(market) + (qty * sell_price), market)
        return jsonify({"ok": True, "trade": trade_item})

    if request.method == "DELETE":
        trade_id = request.args.get("id")
        if trade_id:
            trades = [t for t in trades if str(t.get("id")) != str(trade_id)]
            save_trades(trades, market)
        return jsonify({"ok": True})

@app.route("/api/test-quant-signal")
def api_test_quant_signal():
    ticker = request.args.get("ticker", "NVDA").upper()
    market = request.args.get("market", "US").upper()
    sym_dl = normalize_ticker(ticker, market)
    
    mock_item = {
        "price": 128.80,
        "atr": 2.30,
        "poc": 128.80,
        "fibo_0": 138.00,
        "resistance": 138.00,
        "rsi": 42.5,
        "vol_ratio": 2.4,
        "quant_factors": {
            "ema_slope": True,
            "near_poc": True,
            "rsi_cooldown": True,
            "vol_spike": True
        }
    }
    
    with cache_lock:
        if sym_dl in watchlist_cache and watchlist_cache[sym_dl].get("price"):
            mock_item.update(watchlist_cache[sym_dl])

    ok, msg = send_quant_signal(sym_dl, market, mock_item)
    if ok:
        return jsonify({"ok": True, "message": f"ส่ง Quant Signal ทดสอบของ {ticker} เรียบร้อยแล้ว"})
    return jsonify({"ok": False, "message": msg}), 400

@app.route("/api/test-alert", methods=["GET", "POST"])
def api_test_alert():
    symbol = request.args.get("ticker", "").strip().upper() or "AAPL"
    is_th = symbol.endswith(".BK")
    market_flag = "🇹🇭" if is_th else "🇺🇸"
    display_ticker = symbol.replace(".BK", "")

    test_msg = (
        f"🔔 <b>[ทดสอบระบบ] การแจ้งเตือนทำงานปกติ!</b>\n"
        f"━━━━━━━━━━━━━━━\n"
        f"📈 หุ้น: <b>{market_flag} {display_ticker}</b>\n"
        f"⚡ โหมด: ประหยัด RAM (Lightweight Mode)\n"
        f"⏰ เวลา: {datetime.now().strftime('%H:%M:%S')}"
    )

    success, msg = send_telegram_alert(test_msg)
    if success:
        return jsonify({"ok": True, "message": f"ส่งข้อความทดสอบ {display_ticker} สำเร็จแล้ว"})
    return jsonify({"ok": False, "message": msg}), 400

@app.route("/api/chart/<ticker>")
def api_chart(ticker):
    tf = request.args.get("tf", "3M")
    market = request.args.get("market", "US").upper()
    period, interval = TIMEFRAME_MAP.get(tf, ("3mo", "1d"))

    if not valid_ticker(ticker, market):
        return api_error("สัญลักษณ์หุ้นไม่ถูกต้อง")
    chart_period = "300d" if interval == "1d" and period in {"1mo", "3mo", "6mo"} else period
    try:
        df = download_history(ticker, period=chart_period, interval=interval)
    except RuntimeError:
        return api_error("ไม่สามารถดึงข้อมูลตลาดได้ในขณะนี้", 503)
    if df.empty:
        return jsonify({"error": "ไม่พบข้อมูลของหุ้นตัวนี้"}), 404
    df = flatten_columns(df)

    sma20, sma50, ema200, rsi, macd, macd_signal, macd_hist = compute_indicators(df)
    display_df = df
    display_days = {"1mo": 31, "3mo": 93, "6mo": 186}.get(period)
    if display_days:
        cutoff = pd.Timestamp.now(tz=df.index.tz) - pd.Timedelta(days=display_days)
        display_df = df.loc[df.index >= cutoff]
    dates = [d.strftime("%Y-%m-%d %H:%M") for d in display_df.index.to_pydatetime()]

    def clean(series):
        return [None if pd.isna(v) else round(float(v), 4) for v in series]

    auto_sup, auto_res, support_levels, resistance_levels = compute_support_resistance(display_df)
    fibo_levels = compute_fibonacci_levels(display_df)
    poc_price = compute_volume_profile(display_df)

    support = auto_sup
    resistance = auto_res

    h_data = load_holdings(market)
    holding_info = h_data.get(ticker)
    trailing_stop = compute_trailing_stop(df, holding_info)

    gc.collect()

    return jsonify({
        "dates": dates,
        "open": clean(display_df["Open"]),
        "high": clean(display_df["High"]),
        "low": clean(display_df["Low"]),
        "close": clean(display_df["Close"]),
        "volume": clean(display_df["Volume"]),
        "sma20": clean(sma20.reindex(display_df.index)),
        "sma50": clean(sma50.reindex(display_df.index)),
        "ema200": clean(ema200.reindex(display_df.index)),
        "rsi": clean(rsi.reindex(display_df.index)),
        "macd": clean(macd.reindex(display_df.index)),
        "macd_signal": clean(macd_signal.reindex(display_df.index)),
        "macd_hist": clean(macd_hist.reindex(display_df.index)),
        "support": support,
        "resistance": resistance,
        "is_custom": False,
        "support_levels": support_levels,
        "resistance_levels": resistance_levels,
        "fibo_levels": fibo_levels,
        "poc_price": poc_price,
        "trailing_stop": trailing_stop,
    })

if __name__ == "__main__":
    ensure_background_worker()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)