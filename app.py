from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
import requests
from urllib.parse import unquote

app = Flask(__name__)

# Configure CORS to allow all origins for all routes
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})


# Load API keys
def load_keys():
    try:
        with open('keys.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"keys": []}


# Discord channel ID
DISCORD_CHANNEL_ID = "1385836633227530380"


def send_discord_message(email, message, bot_token):
    # Format message - replace \ with actual line breaks
    formatted_message = message.replace('\\', '\n')

    # Create embed
    embed = {
        "title": "📧 New Message",
        "color": 0x00ff00,
        "fields": [
            {
                "name": "📧 Email",
                "value": email,
                "inline": False
            },
            {
                "name": "💬 Message",
                "value": formatted_message[:1024],  # Limit field value to Discord's max
                "inline": False
            }
        ],
        "timestamp": None,
        "footer": {
            "text": "Customer Service API"
        }
    }

    # If message is longer than 1024 chars, add additional fields
    if len(formatted_message) > 1024:
        remaining_message = formatted_message[1024:]
        field_count = 2

        while remaining_message and field_count < 25:  # Discord max 25 fields per embed
            chunk_size = min(1024, len(remaining_message))
            embed["fields"].append({
                "name": f"💬 Message (continued {field_count - 1})",
                "value": remaining_message[:chunk_size],
                "inline": False
            })
            remaining_message = remaining_message[chunk_size:]
            field_count += 1

    payload = {
        "embeds": [embed]
    }

    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }

    url = f"https://discord.com/api/v9/channels/{DISCORD_CHANNEL_ID}/messages"

    try:
        response = requests.post(url, json=payload, headers=headers)
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending Discord message: {e}")
        return False


@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "Discord API is running",
        "usage": "/api/{key}/email-{email}/message-{message}"
    })


@app.route('/api/<key>/send', methods=['POST'])
def send_message_post(key):
    """POST endpoint for longer messages"""
    # Load current keys
    keys_data = load_keys()
    valid_keys = keys_data.get("keys", [])

    # Check if key is valid
    if key not in valid_keys:
        return jsonify({
            "error": "Invalid API key",
            "status": "unauthorized"
        }), 401

    # Get Discord bot token from environment (check both cases)
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        return jsonify({
            "error": "Discord bot token not configured",
            "status": "server_error"
        }), 500

    # Get data from JSON body
    data = request.get_json()
    if not data:
        return jsonify({
            "error": "No JSON data provided",
            "status": "bad_request"
        }), 400

    email = data.get('email')
    message = data.get('message')

    if not email or not message:
        return jsonify({
            "error": "Email and message are required",
            "status": "bad_request"
        }), 400

    # Send message to Discord
    success = send_discord_message(email, message, bot_token)

    if success:
        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": email,
            "sent_message": message.replace('\\', '\n')
        })
    else:
        return jsonify({
            "error": "Failed to send message to Discord",
            "status": "discord_error"
        }), 500


@app.route('/api/<key>/email-<email>/message-<path:message>')
def send_message_get(key, email, message):
    # Load current keys
    keys_data = load_keys()
    valid_keys = keys_data.get("keys", [])

    # Check if key is valid
    if key not in valid_keys:
        return jsonify({
            "error": "Invalid API key",
            "status": "unauthorized"
        }), 401

    # Get Discord bot token from environment (check both cases)
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        return jsonify({
            "error": "Discord bot token not configured",
            "status": "server_error"
        }), 500

    # Decode URL-encoded message and email
    decoded_message = unquote(message)
    decoded_email = unquote(email)

    # Send message to Discord
    success = send_discord_message(decoded_email, decoded_message, bot_token)

    if success:
        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": decoded_email,
            "sent_message": decoded_message.replace('\\', '\n')
        })
    else:
        return jsonify({
            "error": "Failed to send message to Discord",
            "status": "discord_error"
        }), 500


@app.route('/debug')
def debug():
    """Debug endpoint to check environment variables"""
    discord_token_1 = os.getenv('DISCORD_BOT_TOKEN')
    discord_token_2 = os.getenv('discord_bot_token')

    return jsonify({
        "DISCORD_BOT_TOKEN": "SET" if discord_token_1 else "NOT SET",
        "discord_bot_token": "SET" if discord_token_2 else "NOT SET",
        "env_vars": list(os.environ.keys())
    })


@app.route('/keys', methods=['GET'])
def get_keys():
    """Admin endpoint to view current keys (remove in production)"""
    keys_data = load_keys()
    return jsonify(keys_data)


# Handle preflight OPTIONS requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response


if __name__ == '__main__':
    app.run(debug=True)