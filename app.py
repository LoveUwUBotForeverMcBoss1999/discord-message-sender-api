from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
import requests
import re
from urllib.parse import unquote, urlparse

app = Flask(__name__)

# Configure CORS to allow all origins for all routes
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Origin", "Referer"]
    }
})


# Load API keys
def load_keys():
    try:
        with open('keys.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"keys": {}}


# Email validation function
def validate_email(email):
    """Validate email format using regex"""
    # Basic email pattern: {name}@{domain}
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_url_access(key, request_origin, request_referer):
    """
    Validate if the request is coming from an authorized URL
    Returns (is_valid, error_message)
    """
    keys_data = load_keys()
    valid_keys = keys_data.get("keys", {})

    if key not in valid_keys:
        return False, "Invalid API key"

    key_config = valid_keys[key]
    authorized_url = key_config.get("url")

    if not authorized_url:
        return False, "No authorized URL configured for this key"

    # Parse the authorized URL
    try:
        parsed_auth_url = urlparse(authorized_url)
        auth_domain = parsed_auth_url.netloc.lower()
        auth_scheme = parsed_auth_url.scheme.lower()

        # Only allow HTTPS (except for localhost/127.0.0.1 for development)
        if auth_scheme != 'https':
            if not (auth_domain.startswith('localhost') or auth_domain.startswith('127.0.0.1')):
                return False, "Only HTTPS URLs are allowed (except localhost for development)"

    except Exception as e:
        return False, f"Invalid authorized URL format: {str(e)}"

    # Check both Origin and Referer headers
    sources_to_check = []

    if request_origin:
        sources_to_check.append(('Origin', request_origin))

    if request_referer:
        sources_to_check.append(('Referer', request_referer))

    if not sources_to_check:
        return False, "No Origin or Referer header found. Request must come from a web browser."

    # Validate each source
    for header_name, source_url in sources_to_check:
        try:
            parsed_source = urlparse(source_url)
            source_domain = parsed_source.netloc.lower()
            source_scheme = parsed_source.scheme.lower()

            # Check if domain matches
            if source_domain == auth_domain and source_scheme == auth_scheme:
                return True, None

        except Exception:
            continue  # Try next source if this one fails to parse

    return False, f"Request must come from authorized URL: {authorized_url}"


def check_bot_in_server(server_id, bot_token):
    """Check if bot is in the specified server"""
    url = f"https://discord.com/api/v9/guilds/{server_id}"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return True
        elif response.status_code == 403:
            return False  # Bot not in server or no permission
        elif response.status_code == 404:
            return False  # Server not found
        else:
            return False
    except Exception as e:
        print(f"Error checking bot server access: {e}")
        return False


def check_channel_access(channel_id, bot_token):
    """Check if bot can access the specified channel"""
    url = f"https://discord.com/api/v9/channels/{channel_id}"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return True
        elif response.status_code == 403:
            return False  # No permission to access channel
        elif response.status_code == 404:
            return False  # Channel not found
        else:
            return False
    except Exception as e:
        print(f"Error checking bot channel access: {e}")
        return False


def send_discord_message(email, message, bot_token, channel_id, source_info=None):
    # Format message - replace \ with actual line breaks
    formatted_message = message.replace('\\', '\n')

    # Add source info for security logging
    source_text = ""
    if source_info:
        source_text = f"\n🔗 **Source:** {source_info}"

    url = f"https://discord.com/api/v9/channels/{channel_id}/messages"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }

    # If message is short enough, use embed description (4096 char limit)
    if len(formatted_message) <= 3800:  # Leave buffer for source info
        embed = {
            "title": "📧 New Message",
            "description": f"**📧 Email:** {email}\n\n**💬 Message:**\n{formatted_message}{source_text}",
            "color": 0x00ff00,
            "footer": {
                "text": "Customer Service API - Secure"
            }
        }

        payload = {"embeds": [embed]}

        try:
            response = requests.post(url, json=payload, headers=headers)
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending Discord message: {e}")
            return False

    # For very long messages, send as multiple messages
    else:
        try:
            # Send header message first
            header_embed = {
                "title": "📧 New Message",
                "description": f"**📧 Email:** {email}\n\n**💬 Message:** (Long message - sent in parts){source_text}",
                "color": 0x00ff00,
                "footer": {
                    "text": "Customer Service API - Secure"
                }
            }

            header_payload = {"embeds": [header_embed]}
            response = requests.post(url, json=header_payload, headers=headers)

            if response.status_code != 200:
                return False

            # Send message content in chunks as regular messages (not embeds)
            chunk_size = 1900  # Discord message limit is 2000 chars
            message_parts = [formatted_message[i:i + chunk_size] for i in range(0, len(formatted_message), chunk_size)]

            for i, part in enumerate(message_parts):
                part_payload = {
                    "content": f"```\n{part}\n```"  # Use code block to preserve formatting
                }

                response = requests.post(url, json=part_payload, headers=headers)
                if response.status_code != 200:
                    return False

            return True

        except Exception as e:
            print(f"Error sending Discord message: {e}")
            return False


@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "message": "Discord API is running with URL authentication",
        "usage": "/api/{key}/email-{email}/message-{message}",
        "post_usage": "/api/{key}/send",
        "security": "Requests must come from authorized URLs only"
    })


@app.route('/api/<key>/send', methods=['POST'])
def send_message_post(key):
    """POST endpoint for longer messages with URL authentication"""

    # Get origin and referer from headers
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')

    # Validate URL access first
    is_valid, error_msg = validate_url_access(key, origin, referer)
    if not is_valid:
        return jsonify({
            "error": error_msg,
            "status": "unauthorized",
            "security_note": "Request must come from authorized website"
        }), 403

    # Load current keys
    keys_data = load_keys()
    valid_keys = keys_data.get("keys", {})

    # Get key configuration
    key_config = valid_keys[key]
    channel_id = key_config.get("channel_id")
    server_id = key_config.get("server_id")

    if not channel_id or not server_id:
        return jsonify({
            "error": "Key configuration incomplete - missing channel_id or server_id",
            "status": "server_error"
        }), 500

    # Get Discord bot token from environment (check both cases)
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        return jsonify({
            "error": "Discord bot token not configured",
            "status": "server_error"
        }), 500

    # Check if bot is in the server
    if not check_bot_in_server(server_id, bot_token):
        return jsonify({
            "error": f"Bot is not in the server (ID: {server_id}) or lacks permissions",
            "status": "bot_access_error",
            "server_id": server_id
        }), 403

    # Check if bot can access the channel
    if not check_channel_access(channel_id, bot_token):
        return jsonify({
            "error": f"Bot cannot access the channel (ID: {channel_id}) or channel doesn't exist",
            "status": "channel_access_error",
            "channel_id": channel_id
        }), 403

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

    # Validate email format
    if not validate_email(email):
        return jsonify({
            "error": "Invalid email format. Email must be in format: name@domain.com",
            "status": "bad_request"
        }), 400

    # Prepare source info for logging
    source_info = origin or referer or "Unknown"

    # Send message to Discord
    success = send_discord_message(email, message, bot_token, channel_id, source_info)

    if success:
        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": email,
            "sent_message": message.replace('\\', '\n'),
            "channel_id": channel_id,
            "server_id": server_id,
            "source": source_info
        })
    else:
        return jsonify({
            "error": "Failed to send message to Discord",
            "status": "discord_error",
            "channel_id": channel_id
        }), 500


@app.route('/api/<key>/email-<email>/message-<path:message>')
def send_message_get(key, email, message):
    """GET endpoint with URL authentication"""

    # Get origin and referer from headers
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')

    # Validate URL access first
    is_valid, error_msg = validate_url_access(key, origin, referer)
    if not is_valid:
        return jsonify({
            "error": error_msg,
            "status": "unauthorized",
            "security_note": "Request must come from authorized website"
        }), 403

    # Load current keys
    keys_data = load_keys()
    valid_keys = keys_data.get("keys", {})

    # Get key configuration
    key_config = valid_keys[key]
    channel_id = key_config.get("channel_id")
    server_id = key_config.get("server_id")

    if not channel_id or not server_id:
        return jsonify({
            "error": "Key configuration incomplete - missing channel_id or server_id",
            "status": "server_error"
        }), 500

    # Get Discord bot token from environment (check both cases)
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        return jsonify({
            "error": "Discord bot token not configured",
            "status": "server_error"
        }), 500

    # Check if bot is in the server
    if not check_bot_in_server(server_id, bot_token):
        return jsonify({
            "error": f"Bot is not in the server (ID: {server_id}) or lacks permissions",
            "status": "bot_access_error",
            "server_id": server_id
        }), 403

    # Check if bot can access the channel
    if not check_channel_access(channel_id, bot_token):
        return jsonify({
            "error": f"Bot cannot access the channel (ID: {channel_id}) or channel doesn't exist",
            "status": "channel_access_error",
            "channel_id": channel_id
        }), 403

    # Decode URL-encoded message and email
    decoded_message = unquote(message)
    decoded_email = unquote(email)

    # Additional decoding to handle double encoding
    decoded_email = unquote(decoded_email)
    decoded_message = unquote(decoded_message)

    print(f"Original email: {email}")
    print(f"Decoded email: {decoded_email}")
    print(f"Original message: {message}")
    print(f"Decoded message: {decoded_message}")

    # Validate email format
    if not validate_email(decoded_email):
        return jsonify({
            "error": "Invalid email format. Email must be in format: name@domain.com",
            "status": "bad_request",
            "received_email": decoded_email
        }), 400

    # Prepare source info for logging
    source_info = origin or referer or "Unknown"

    # Send message to Discord
    success = send_discord_message(decoded_email, decoded_message, bot_token, channel_id, source_info)

    if success:
        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": decoded_email,
            "sent_message": decoded_message.replace('\\', '\n'),
            "channel_id": channel_id,
            "server_id": server_id,
            "source": source_info
        })
    else:
        return jsonify({
            "error": "Failed to send message to Discord",
            "status": "discord_error",
            "channel_id": channel_id
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


@app.route('/keys/<key>/info', methods=['GET'])
def get_key_info(key):
    """Get information about a specific key"""
    keys_data = load_keys()
    valid_keys = keys_data.get("keys", {})

    if key not in valid_keys:
        return jsonify({
            "error": "Invalid API key",
            "status": "unauthorized"
        }), 401

    key_config = valid_keys[key]

    # Get Discord bot token for validation
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        return jsonify({
            "error": "Discord bot token not configured",
            "status": "server_error"
        }), 500

    channel_id = key_config.get("channel_id")
    server_id = key_config.get("server_id")

    # Check access
    server_access = check_bot_in_server(server_id, bot_token) if server_id else False
    channel_access = check_channel_access(channel_id, bot_token) if channel_id else False

    return jsonify({
        "key": key,
        "config": key_config,
        "access_status": {
            "server_access": server_access,
            "channel_access": channel_access
        }
    })


@app.route('/validate/<key>')
def validate_key_from_url(key):
    """Validate if current request origin is authorized for this key"""
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')

    is_valid, error_msg = validate_url_access(key, origin, referer)

    if is_valid:
        return jsonify({
            "status": "authorized",
            "message": "Request origin is authorized for this key",
            "source": origin or referer
        })
    else:
        return jsonify({
            "status": "unauthorized",
            "error": error_msg,
            "source": origin or referer or "No origin/referer found"
        }), 403


# Handle preflight OPTIONS requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response


@app.route('/api-doc')
def api_documentation():
    """Serve the API documentation HTML page"""
    try:
        with open('document.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content, 200, {'Content-Type': 'text/html; charset=utf-8'}
    except FileNotFoundError:
        return jsonify({
            "error": "Documentation file not found",
            "status": "file_not_found"
        }), 404
    except Exception as e:
        return jsonify({
            "error": f"Error loading documentation: {str(e)}",
            "status": "server_error"
        }), 500


if __name__ == '__main__':
    app.run(debug=True)
