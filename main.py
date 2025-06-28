import os
import logging
import threading
import uuid
import re
import requests
from flask import Flask, request, Response, redirect
from telegram import Bot, Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from datetime import datetime, timezone
import asyncio
import hashlib
import ipaddress  # Added for IPv6 detection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Try importing user_agents with fallback
try:
    from user_agents import parse
    HAVE_USER_AGENTS = True
except ImportError:
    HAVE_USER_AGENTS = False
    logging.warning("user-agents package not installed. Limited device detection available.")

# === Configuration ===
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
WEBHOOK_HOST = os.getenv("WEBHOOK_HOST")

# === Initialize Flask app ===
app = Flask(__name__)

# In-memory storage
tracking_data = {}
telegram_bot = Bot(token=TELEGRAM_BOT_TOKEN)

# Global event loop for bot
telegram_event_loop = None

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?|localhost|\d{1,3}(?:\.\d{1,3}){3}|\[?[A-F0-9]*:[A-F0-9:]+\]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url)

def get_ip_info(ip):
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}",
            timeout=3
        )
        if response.status_code == 200:
            return response.json()
        logging.error(f"IP info request failed with status {response.status_code}")
    except Exception as e:
        logging.error(f"IP info request error: {str(e)}")
    return {}

def detect_architecture(user_agent_str):
    arch_patterns = {
        '64-bit': ['x86_64', 'Win64', 'x64', 'amd64', 'WOW64', 'arm64', 'aarch64'],
        '32-bit': ['i386', 'i686', 'x86']
    }
    for arch, indicators in arch_patterns.items():
        if any(indicator.lower() in user_agent_str.lower() for indicator in indicators):
            return arch
    return "Unknown"

def get_ip_version(ip_address):
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return "IPv6" if ip_obj.version == 6 else "IPv4"
    except ValueError:
        return "Unknown"

def get_device_info(user_agent):
    if HAVE_USER_AGENTS:
        try:
            ua = parse(user_agent)

            os_family = ua.os.family or "Other"
            os_version = ua.os.version_string or ""
            os_full = f"{os_family} {os_version}".strip()

            browser_family = ua.browser.family or "Other"
            browser_version = ua.browser.version_string or ""
            browser_full = f"{browser_family} {browser_version}".strip()

            architecture = detect_architecture(user_agent)

            device_type = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "PC" if ua.is_pc else "Other"

            return {
                "device": {
                    "type": device_type,
                    "brand": ua.device.brand or "Unknown",
                    "model": ua.device.model or "Unknown"
                },
                "os": os_full,
                "browser": browser_full,
                "architecture": architecture,
                "is_bot": ua.is_bot
            }
        except Exception as e:
            logging.error(f"User agent parsing error: {str(e)}")

    return {
        "device": {"type": "Unknown", "brand": "Unknown", "model": "Unknown"},
        "os": "Other",
        "browser": "Other",
        "architecture": "Unknown",
        "is_bot": False
    }

@app.route('/')
def home():
    return "Tracking service is running"

@app.route('/<token>', methods=['GET'])
def track_visit(token):
    if token not in tracking_data:
        return Response("Invalid tracking link", status=404)

    try:
        raw_ip = request.headers.get('X-Forwarded-For')
        visitor_ip = None

        if raw_ip:
            visitor_ip = raw_ip.split(',')[0].strip()
        elif request.remote_addr:
            visitor_ip = request.remote_addr

        if not visitor_ip:
            logging.warning(f"Could not determine visitor IP. Headers: {dict(request.headers)}")
            visitor_ip = "Unknown"

        user_agent = request.headers.get('User-Agent', 'Unknown')
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        ip_info = get_ip_info(visitor_ip)
        device_info = get_device_info(user_agent)
        ip_version = get_ip_version(visitor_ip)

        visit_data = {
            "timestamp": timestamp,
            "ip": visitor_ip,
            "ip_version": ip_version,
            "location": {
                "city": ip_info.get("city", "None"),
                "region": ip_info.get("region", "None"),
                "country": ip_info.get("country", "None"),
                "coordinates": ip_info.get("loc", "None")
            },
            "network": {
                "isp": ip_info.get("org", "None"),
                "asn": ip_info.get("asn", "None")
            },
            "device": device_info
        }

        tracking_data[token]['visits'].append(visit_data)
        tracking_data[token]['visit_count'] += 1

        if telegram_event_loop:
            telegram_event_loop.call_soon_threadsafe(
                asyncio.create_task, send_telegram_alert(token, visit_data)
            )

        return redirect(tracking_data[token]['target_url'], code=302)

    except Exception as e:
        logging.error(f"Error processing visit: {str(e)}")
        return Response("Internal server error", status=500)

# [rest of code remains unchanged below this point...]
