from flask import Flask, jsonify, request
import json
import os
import requests
from urllib.parse import unquote

app = Flask(__name__)

# Discord configuration
DISCORD_CHANNEL_ID = "1385836633227530380"
DISCORD_BOT_TOKEN = os.environ.get('DISCORD_BOT_TOKEN')


def load_api_keys():
    """Load API keys from keys.json file"""
    try:
        with open('keys.json', 'r') as f:
            data = json.load(f)
            return data.get('api_keys', [])
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        return []


def is_valid_api_key(key):
    """Check if the provided API key is valid"""
    api_keys = load_api_keys()
    return key in api_keys


def send_discord_message(email, message):
    """Send message to Discord channel via webhook or bot"""
    if not DISCORD_BOT_TOKEN:
        return False, "Discord bot token not configured"

    # Format the message - replace \\ with actual line breaks
    formatted_message = message.replace('\\', '\n')

    # Create embed
    embed = {
        "title": "📧 New Message",
        "color": 0x00ff00,
        "fields": [
            {
                "name": "From",
                "value": email,
                "inline": True
            },
            {
                "name": "Message",
                "value": formatted_message[:1024],  # Discord embed field limit
                "inline": False
            }
        ],
        "timestamp": None,
        "footer": {
            "text": "Message Service API"
        }
    }

    # Discord API endpoint
    url = f"https://discord.com/api/v10/channels/{DISCORD_CHANNEL_ID}/messages"

    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "embeds": [embed]
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            return True, "Message sent successfully"
        else:
            return False, f"Discord API error: {response.status_code}"
    except Exception as e:
        return False, f"Error sending message: {str(e)}"


@app.route('/', methods=['GET'])
def home():
    """API documentation endpoint"""
    return jsonify({
        "message": "Discord Message API",
        "usage": "/api/{api_key}/email-{email}/message-{message}",
        "note": "Use \\\\ in message for line breaks",
        "status": "active"
    })


@app.route('/api/<api_key>/email-<email>/message-<path:message>', methods=['GET', 'POST'])
def send_message(api_key, email, message):
    """Main endpoint for sending messages"""

    # Validate API key
    if not is_valid_api_key(api_key):
        return jsonify({
            "error": "Invalid API key",
            "status": "unauthorized"
        }), 401

    # URL decode the parameters
    email = unquote(email)
    message = unquote(message)

    # Basic validation
    if not email or not message:
        return jsonify({
            "error": "Email and message are required",
            "status": "bad_request"
        }), 400

    # Validate email format (basic check)
    if '@' not in email:
        return jsonify({
            "error": "Invalid email format",
            "status": "bad_request"
        }), 400

    # Send message to Discord
    success, result = send_discord_message(email, message)

    if success:
        return jsonify({
            "message": "Message sent successfully",
            "status": "success",
            "email": email,
            "discord_channel": DISCORD_CHANNEL_ID
        })
    else:
        return jsonify({
            "error": result,
            "status": "failed"
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "api_keys_loaded": len(load_api_keys()),
        "discord_configured": bool(DISCORD_BOT_TOKEN)
    })


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Endpoint not found",
        "status": "not_found",
        "usage": "/api/{api_key}/email-{email}/message-{message}"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error",
        "status": "error"
    }), 500


if __name__ == '__main__':
    app.run(debug=True)