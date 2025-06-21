from flask import Flask, jsonify, request
import requests
import json
import os
from datetime import datetime

app = Flask(__name__)


# Load API keys
def load_keys():
    try:
        with open('keys.json', 'r') as f:
            return json.load(f)
    except:
        return {"keys": []}


# Discord bot token - you'll need to set this as environment variable
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
DISCORD_CHANNEL_ID = "1385836633227530380"


def send_discord_embed(email, message):
    """Send embed message to Discord channel"""
    if not DISCORD_BOT_TOKEN:
        return False, "Discord bot token not configured"

    # Format message (replace \\ with actual line breaks)
    formatted_message = message.replace('\\', '\n')

    # Create embed
    embed = {
        "title": "📧 New Message Received",
        "description": formatted_message,
        "color": 5814783,  # Blue color
        "fields": [
            {
                "name": "📨 From Email",
                "value": email,
                "inline": True
            },
            {
                "name": "⏰ Timestamp",
                "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "inline": True
            }
        ],
        "footer": {
            "text": "Message sent via API"
        }
    }

    payload = {
        "embeds": [embed]
    }

    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }

    url = f"https://discord.com/api/v10/channels/{DISCORD_CHANNEL_ID}/messages"

    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            return True, "Message sent successfully"
        else:
            return False, f"Discord API error: {response.status_code}"
    except Exception as e:
        return False, f"Request failed: {str(e)}"


@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "message": "Discord API is running",
        "usage": "/api/{key}/email-{email}/message-{message}"
    })


@app.route('/api/<key>/email-<email>/message-<message>')
def send_message(key, email, message):
    """Send message to Discord channel"""

    # Load and validate API key
    keys_data = load_keys()
    valid_keys = keys_data.get("keys", [])

    if key not in valid_keys:
        return jsonify({
            "success": False,
            "error": "Invalid API key"
        }), 401

    # Validate inputs
    if not email or not message:
        return jsonify({
            "success": False,
            "error": "Email and message are required"
        }), 400

    # Send to Discord
    success, result = send_discord_embed(email, message)

    if success:
        return jsonify({
            "success": True,
            "message": result,
            "data": {
                "email": email,
                "message": message.replace('\\', '\n'),
                "channel_id": DISCORD_CHANNEL_ID
            }
        })
    else:
        return jsonify({
            "success": False,
            "error": result
        }), 500


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "keys_loaded": len(load_keys().get("keys", []))
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found",
        "usage": "/api/{key}/email-{email}/message-{message}"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


if __name__ == '__main__':
    app.run(debug=True)