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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

try:
    from user_agents import parse
    HAVE_USER_AGENTS = True
except ImportError:
    HAVE_USER_AGENTS = False
    logging.warning("user-agents package not installed. Limited device detection available.")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
WEBHOOK_HOST = os.getenv("WEBHOOK_HOST")

app = Flask(__name__)
tracking_data = {}
telegram_bot = Bot(token=TELEGRAM_BOT_TOKEN)
telegram_event_loop = None

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?))'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url)

def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}", timeout=3)
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
        forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)
        ip_list = [ip.strip() for ip in forwarded_for.split(',')]
        ipv4, ipv6 = None, None

        for ip in ip_list:
            if ':' in ip:
                ipv6 = ipv6 or ip
            else:
                ipv4 = ipv4 or ip

        visitor_ip = ipv6 or ipv4 or request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        ip_info = get_ip_info(visitor_ip)
        device_info = get_device_info(user_agent)

        visit_data = {
            "timestamp": timestamp,
            "ip": {
                "ipv4": ipv4 or "N/A",
                "ipv6": ipv6 or "N/A"
            },
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

# Remaining functions remain unchanged...
# (send_telegram_alert, start, track, ips, help_command, favicon, not_found, run_flask, run_bot, etc.)
