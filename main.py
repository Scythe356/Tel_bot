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
import ipaddress

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
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
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


def extract_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.remote_addr


def get_ip_version(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return "IPv6" if ip_obj.version == 6 else "IPv4"
    except ValueError:
        return "Unknown"


@app.route('/')
def home():
    return "Tracking service is running"


@app.route('/<token>', methods=['GET'])
def track_visit(token):
    if token not in tracking_data:
        return Response("Invalid tracking link", status=404)

    try:
        visitor_ip = extract_client_ip()
        ip_version = get_ip_version(visitor_ip)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        ip_info = get_ip_info(visitor_ip)
        device_info = get_device_info(user_agent)

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


async def send_telegram_alert(token, visit_data):
    try:
        message = f"""\n🆕 New visit to tracking link: {token[:8]}...
🌐 Target: {tracking_data[token]['target_url']}
👥 Total Visits: {tracking_data[token]['visit_count']}

🕒 {visit_data['timestamp']}

📍 Location:
  🏙️ {visit_data['location']['city']}
  🌆 {visit_data['location']['region']}
  🌎 {visit_data['location']['country']}
  📌 {visit_data['location']['coordinates']}

📶 Network:
  🏢 {visit_data['network']['isp']}
  🔢 ASN: {visit_data['network']['asn']} 
  🖥️ {visit_data['ip']} ({visit_data['ip_version']})

📱 Device:
  💻 {visit_data['device']['os']} ({visit_data['device']['architecture']})
  🌐 {visit_data['device']['browser']}
  📲 {visit_data['device']['device']['type']} - {visit_data['device']['device']['brand']} {visit_data['device']['device']['model']}
  🤖 {'Bot detected' if visit_data['device']['is_bot'] else 'Human'}"""

        await telegram_bot.send_message(
            chat_id=tracking_data[token]['chat_id'],
            text=message,
            disable_web_page_preview=True
        )
    except Exception as e:
        logging.error(f"Failed to send Telegram alert: {str(e)}")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.info(f"/start received from {update.effective_user.id}")
    await update.message.reply_text(
        "🔗 URL Tracking Bot\n\n"
        "Commands:\n"
        "/track <url> - Create tracking link\n"
        "/ips <token> - View visits (as alert)\n"
        "/help - Show this message"
    )


async def track(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Please provide a URL\nExample: /track https://example.com")
        return

    url = ' '.join(context.args).strip()
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'

    if not is_valid_url(url):
        await update.message.reply_text("Invalid URL format. Please include http:// or https://")
        return

    token = hashlib.md5(url.encode()).hexdigest()[:8]
    tracking_data[token] = {
        'target_url': url,
        'chat_id': update.effective_chat.id,
        'visits': [],
        'visit_count': 0
    }

    tracking_url = f"{WEBHOOK_HOST}/{token}"
    logging.info(f"New tracking link created by {update.effective_user.id}: {tracking_url}")

    await update.message.reply_text(
        f"✅ Tracking link created\n\n"
        f"🌐 Target: {url}\n"
        f"🔗 Tracking URL: {tracking_url}\n\n"
        f"You'll receive alerts when visited.",
        disable_web_page_preview=True
    )


async def ips(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Please provide a tracking token\nExample: /ips abc12345")
        return

    token = context.args[0]
    if token not in tracking_data:
        await update.message.reply_text(f"❌ No data found for token: {token}")
        return

    visits = tracking_data[token]['visits']
    if not visits:
        await update.message.reply_text(f"ℹ️ No visits recorded yet for token: {token}")
        return

    for i, visit in enumerate(visits, start=1):
        try:
            message = f"""\n📥 Visit #{i} for tracking link: {token[:8]}...
🌐 Target: {tracking_data[token]['target_url']}
👥 Total Visits: {tracking_data[token]['visit_count']}

🕒 {visit['timestamp']}

📍 Location:
  🏙️ {visit['location']['city']}
  🌆 {visit['location']['region']}
  🌎 {visit['location']['country']}
  📌 {visit['location']['coordinates']}

📶 Network:
  🏢 {visit['network']['isp']}
  🔢 ASN: {visit['network']['asn']} 
  🖥️ {visit['ip']} ({visit['ip_version']})

📱 Device:
  💻 {visit['device']['os']} ({visit['device']['architecture']})
  🌐 {visit['device']['browser']}
  📲 {visit['device']['device']['type']} - {visit['device']['device']['brand']} {visit['device']['device']['model']}
  🤖 {'Bot detected' if visit['device']['is_bot'] else 'Human'}"""

            await update.message.reply_text(message, disable_web_page_preview=True)

        except Exception as e:
            logging.error(f"Error sending visit #{i} info: {str(e)}")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start(update, context)


@app.route('/favicon.ico')
def favicon():
    return Response(status=204)


@app.errorhandler(404)
def not_found(e):
    return Response("URL not found on this server", status=404)


def run_flask():
    logging.info("Starting Flask server...")
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)


def run_bot():
    global telegram_event_loop
    logging.info("Starting Telegram bot...")
    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("track", track))
    application.add_handler(CommandHandler("ips", ips))
    application.add_handler(CommandHandler("help", help_command))
    telegram_event_loop = asyncio.get_event_loop()
    application.run_polling()


if __name__ == "__main__":
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    run_bot()
