from flask import Flask, jsonify, request
import json
import os
import requests
from urllib.parse import unquote

app = Flask(__name__)

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
                "value": formatted_message,
                "inline": False
            }
        ],
        "timestamp": None,
        "footer": {
            "text": "Customer Service API"
        }
    }
    
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

@app.route('/api/<key>/email-<email>/message-<path:message>')
def send_message(key, email, message):
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
    
    # Decode URL-encoded message
    decoded_message = unquote(message)
    
    # Send message to Discord
    success = send_discord_message(email, decoded_message, bot_token)
    
    if success:
        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": email,
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

if __name__ == '__main__':
    app.run(debug=True)
