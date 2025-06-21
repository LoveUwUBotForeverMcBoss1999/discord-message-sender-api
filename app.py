from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
import requests
import re
from urllib.parse import unquote, urlparse
from datetime import datetime

app = Flask(__name__)

# Configure CORS to allow all origins for all routes
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Origin", "Referer"]
    }
})

# Logging configuration
LOG_CHANNEL_ID = "1386035168896090263"  # Your specified log channel


# Load API keys
def load_keys():
    try:
        with open('keys.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"keys": {}}


def send_usage_log(api_key, endpoint_type, user_email=None, source_url=None, status="success"):
    """
    Send usage log to Discord logging channel

    Args:
        api_key: The API key that was used
        endpoint_type: Type of endpoint used (GET/POST)
        user_email: Email of the user who sent the message (optional)
        source_url: URL where the request came from (optional)
        status: Status of the request (success/error)
    """
    try:
        # Get Discord bot token
        bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
        if not bot_token:
            print("Warning: Cannot send usage log - Discord bot token not configured")
            return False

        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Create status emoji
        status_emoji = "✅" if status == "success" else "❌"

        # Prepare log message
        log_description = f"\n`{api_key}` Used right now\n"

        # Add additional context
        context_info = []
        if endpoint_type:
            context_info.append(f"**Method:** {endpoint_type}")
        if user_email:
            context_info.append(f"**User Email:** {user_email}")
        if source_url:
            context_info.append(f"**Source:** {source_url}")
        context_info.append(f"**Status:** {status_emoji} {status.upper()}")
        context_info.append(f"**Time:** {timestamp}")

        if context_info:
            log_description += "\n" + "\n".join(context_info)

        # Create embed for logging
        embed = {
            "description": log_description,
            "color": 0x00ff00 if status == "success" else 0xff0000,
            "footer": {
                "text": "API Usage Logger"
            }
        }

        # Send log message
        url = f"https://discord.com/api/v9/channels/{LOG_CHANNEL_ID}/messages"
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }

        payload = {"embeds": [embed]}

        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 200:
            print(f"Usage log sent successfully for API key: {api_key}")
            return True
        else:
            print(f"Failed to send usage log. Status code: {response.status_code}")
            return False

    except Exception as e:
        print(f"Error sending usage log: {e}")
        return False


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


def check_user_in_server(user_id, server_id, bot_token):
    """Check if user is in the specified server"""
    url = f"https://discord.com/api/v9/guilds/{server_id}/members/{user_id}"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return True, response.json()
        elif response.status_code == 404:
            return False, None  # User not in server
        else:
            return False, None
    except Exception as e:
        print(f"Error checking user server membership: {e}")
        return False, None


def check_user_admin_permissions(user_id, server_id, bot_token):
    """
    Check if user has administrator permissions in the server
    Returns (has_admin, error_message)
    """
    try:
        # First check if user is in server
        is_member, member_data = check_user_in_server(user_id, server_id, bot_token)

        if not is_member:
            return False, "User is not a member of this server"

        # Get user's roles
        user_roles = member_data.get('roles', [])

        # Get server info to check roles
        guild_url = f"https://discord.com/api/v9/guilds/{server_id}"
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }

        guild_response = requests.get(guild_url, headers=headers)

        if guild_response.status_code != 200:
            return False, "Could not fetch server information"

        guild_data = guild_response.json()

        # Check if user is server owner
        if str(guild_data.get('owner_id')) == str(user_id):
            return True, None

        # Get all roles in the server
        roles_url = f"https://discord.com/api/v9/guilds/{server_id}/roles"
        roles_response = requests.get(roles_url, headers=headers)

        if roles_response.status_code != 200:
            return False, "Could not fetch server roles"

        server_roles = roles_response.json()

        # Check if any of user's roles have administrator permission
        # Administrator permission bit is 0x8 (8)
        ADMINISTRATOR_PERMISSION = 8

        for role in server_roles:
            if role['id'] in user_roles:
                permissions = int(role.get('permissions', 0))
                if permissions & ADMINISTRATOR_PERMISSION:
                    return True, None

        return False, "User does not have administrator permissions in this server"

    except Exception as e:
        print(f"Error checking user admin permissions: {e}")
        return False, f"Error checking permissions: {str(e)}"


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
        "message": "Discord API is running with URL authentication, owner verification, and usage logging",
        "usage": "/api/{key}/email-{email}/message-{message}",
        "post_usage": "/api/{key}/send",
        "security": [
            "Requests must come from authorized URLs only",
            "API keys can only be created via Discord bot command",
            "API owner must have administrator permissions in target server",
            "All API usage is logged to Discord for monitoring"
        ]
    })


@app.route('/api/<key>/send', methods=['POST'])
def send_message_post(key):
    """POST endpoint for longer messages with URL authentication, owner verification, and logging"""

    # Get origin and referer from headers
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    source_info = origin or referer or "Unknown"

    # Validate URL access first
    is_valid, error_msg = validate_url_access(key, origin, referer)
    if not is_valid:
        # Log failed attempt
        send_usage_log(key, "POST", source_url=source_info, status="unauthorized")
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
    owner_id = key_config.get("owner_id")

    if not channel_id or not server_id or not owner_id:
        send_usage_log(key, "POST", source_url=source_info, status="config_error")
        return jsonify({
            "error": "Key configuration incomplete - missing channel_id, server_id, or owner_id",
            "status": "server_error"
        }), 500

    # Get Discord bot token from environment (check both cases)
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        send_usage_log(key, "POST", source_url=source_info, status="token_error")
        return jsonify({
            "error": "Discord bot token not configured",
            "status": "server_error"
        }), 500

    # Check if bot is in the server
    if not check_bot_in_server(server_id, bot_token):
        send_usage_log(key, "POST", source_url=source_info, status="bot_access_error")
        return jsonify({
            "error": f"Bot is not in the server (ID: {server_id}) or lacks permissions",
            "status": "bot_access_error",
            "server_id": server_id
        }), 403

    # Check if bot can access the channel
    if not check_channel_access(channel_id, bot_token):
        send_usage_log(key, "POST", source_url=source_info, status="channel_access_error")
        return jsonify({
            "error": f"Bot cannot access the channel (ID: {channel_id}) or channel doesn't exist",
            "status": "channel_access_error",
            "channel_id": channel_id
        }), 403

    # 🔐 SECURITY CHECK: Verify API owner has admin permissions in the server
    has_admin, admin_error = check_user_admin_permissions(owner_id, server_id, bot_token)
    if not has_admin:
        send_usage_log(key, "POST", source_url=source_info, status="permission_denied")
        return jsonify({
            "error": f"API owner does not have administrator permissions in server: {admin_error}",
            "status": "permission_denied",
            "owner_id": owner_id,
            "server_id": server_id,
            "security_note": "Only users with administrator permissions can use API keys for this server"
        }), 403

    # Get data from JSON body
    data = request.get_json()
    if not data:
        send_usage_log(key, "POST", source_url=source_info, status="bad_request")
        return jsonify({
            "error": "No JSON data provided",
            "status": "bad_request"
        }), 400

    email = data.get('email')
    message = data.get('message')

    if not email or not message:
        send_usage_log(key, "POST", user_email=email, source_url=source_info, status="bad_request")
        return jsonify({
            "error": "Email and message are required",
            "status": "bad_request"
        }), 400

    # Validate email format
    if not validate_email(email):
        send_usage_log(key, "POST", user_email=email, source_url=source_info, status="invalid_email")
        return jsonify({
            "error": "Invalid email format. Email must be in format: name@domain.com",
            "status": "bad_request"
        }), 400

    # Send message to Discord
    success = send_discord_message(email, message, bot_token, channel_id, source_info)

    if success:
        # Log successful usage
        send_usage_log(key, "POST", user_email=email, source_url=source_info, status="success")

        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": email,
            "sent_message": message.replace('\\', '\n'),
            "channel_id": channel_id,
            "server_id": server_id,
            "owner_id": owner_id,
            "source": source_info,
            "security_verified": "API owner has administrator permissions"
        })
    else:
        # Log failed message sending
        send_usage_log(key, "POST", user_email=email, source_url=source_info, status="discord_error")

        return jsonify({
            "error": "Failed to send message to Discord",
            "status": "discord_error",
            "channel_id": channel_id
        }), 500


@app.route('/api/<key>/email-<email>/message-<path:message>')
def send_message_get(key, email, message):
    """GET endpoint with URL authentication, owner verification, and logging"""

    # Get origin and referer from headers
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    source_info = origin or referer or "Unknown"

    # Validate URL access first
    is_valid, error_msg = validate_url_access(key, origin, referer)
    if not is_valid:
        # Log failed attempt
        send_usage_log(key, "GET", source_url=source_info, status="unauthorized")
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
    owner_id = key_config.get("owner_id")

    if not channel_id or not server_id or not owner_id:
        send_usage_log(key, "GET", source_url=source_info, status="config_error")
        return jsonify({
            "error": "Key configuration incomplete - missing channel_id, server_id, or owner_id",
            "status": "server_error"
        }), 500

    # Get Discord bot token from environment (check both cases)
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        send_usage_log(key, "GET", source_url=source_info, status="token_error")
        return jsonify({
            "error": "Discord bot token not configured",
            "status": "server_error"
        }), 500

    # Check if bot is in the server
    if not check_bot_in_server(server_id, bot_token):
        send_usage_log(key, "GET", source_url=source_info, status="bot_access_error")
        return jsonify({
            "error": f"Bot is not in the server (ID: {server_id}) or lacks permissions",
            "status": "bot_access_error",
            "server_id": server_id
        }), 403

    # Check if bot can access the channel
    if not check_channel_access(channel_id, bot_token):
        send_usage_log(key, "GET", source_url=source_info, status="channel_access_error")
        return jsonify({
            "error": f"Bot cannot access the channel (ID: {channel_id}) or channel doesn't exist",
            "status": "channel_access_error",
            "channel_id": channel_id
        }), 403

    # 🔐 SECURITY CHECK: Verify API owner has admin permissions in the server
    has_admin, admin_error = check_user_admin_permissions(owner_id, server_id, bot_token)
    if not has_admin:
        send_usage_log(key, "GET", source_url=source_info, status="permission_denied")
        return jsonify({
            "error": f"API owner does not have administrator permissions in server: {admin_error}",
            "status": "permission_denied",
            "owner_id": owner_id,
            "server_id": server_id,
            "security_note": "Only users with administrator permissions can use API keys for this server"
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
        send_usage_log(key, "GET", user_email=decoded_email, source_url=source_info, status="invalid_email")
        return jsonify({
            "error": "Invalid email format. Email must be in format: name@domain.com",
            "status": "bad_request",
            "received_email": decoded_email
        }), 400

    # Send message to Discord
    success = send_discord_message(decoded_email, decoded_message, bot_token, channel_id, source_info)

    if success:
        # Log successful usage
        send_usage_log(key, "GET", user_email=decoded_email, source_url=source_info, status="success")

        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": decoded_email,
            "sent_message": decoded_message.replace('\\', '\n'),
            "channel_id": channel_id,
            "server_id": server_id,
            "owner_id": owner_id,
            "source": source_info,
            "security_verified": "API owner has administrator permissions"
        })
    else:
        # Log failed message sending
        send_usage_log(key, "GET", user_email=decoded_email, source_url=source_info, status="discord_error")

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
        "log_channel_id": LOG_CHANNEL_ID,
        "env_vars": list(os.environ.keys())
    })


@app.route('/keys', methods=['GET'])
def get_keys():
    """Admin endpoint to view current keys (remove in production)"""
    keys_data = load_keys()
    return jsonify(keys_data)


@app.route('/keys/<key>/info', methods=['GET'])
def get_key_info(key):
    """Get information about a specific key with security validation"""
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
    owner_id = key_config.get("owner_id")

    # Check access
    server_access = check_bot_in_server(server_id, bot_token) if server_id else False
    channel_access = check_channel_access(channel_id, bot_token) if channel_id else False

    # Check owner permissions
    has_admin, admin_error = check_user_admin_permissions(owner_id, server_id,
                                                          bot_token) if owner_id and server_id else (False,
                                                                                                     "Missing owner_id or server_id")

    return jsonify({
        "key": key,
        "owner_id": owner_id,
        "config": key_config,
        "access_status": {
            "server_access": server_access,
            "channel_access": channel_access,
            "owner_has_admin": has_admin,
            "admin_check_error": admin_error
        },
        "security_status": "SECURE" if (server_access and channel_access and has_admin) else "INSECURE",
        "logging": {
            "enabled": True,
            "log_channel": LOG_CHANNEL_ID
        }
    })


@app.route('/validate/<key>')
def validate_key_from_url(key):
    """Validate if current request origin is authorized for this key and check owner permissions"""
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')

    # Check URL authorization
    is_valid, error_msg = validate_url_access(key, origin, referer)

    if not is_valid:
        return jsonify({
            "status": "unauthorized",
            "error": error_msg,
            "source": origin or referer or "No origin/referer found"
        }), 403

    # Load key config
    keys_data = load_keys()
    valid_keys = keys_data.get("keys", {})
    key_config = valid_keys[key]

    owner_id = key_config.get("owner_id")
    server_id = key_config.get("server_id")

    # Get Discord bot token
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        return jsonify({
            "status": "server_error",
            "error": "Discord bot token not configured"
        }), 500

    # Check owner permissions
    has_admin, admin_error = check_user_admin_permissions(owner_id, server_id,
                                                          bot_token) if owner_id and server_id else (False,
                                                                                                     "Missing owner_id or server_id")

    return jsonify({
        "status": "authorized" if has_admin else "permission_denied",
        "message": "Request origin is authorized for this key and owner has admin permissions" if has_admin else f"Owner lacks admin permissions: {admin_error}",
        "source": origin or referer,
        "owner_has_admin": has_admin,
        "security_verified": has_admin
    })


@app.route('/invite-link')
def get_bot_invite_link():
    """Generate Discord bot invite link with required permissions"""

    # Get Discord bot token
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        return jsonify({
            "error": "Discord bot token not configured",
            "status": "server_error"
        }), 500

    # Get bot's application ID from the token or Discord API
    try:
        # Get bot info to extract application ID
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }

        response = requests.get("https://discord.com/api/v9/oauth2/applications/@me", headers=headers)

        if response.status_code == 200:
            bot_info = response.json()
            client_id = bot_info.get('id')
            bot_name = bot_info.get('name', 'Unknown Bot')

            # Required permissions for sending messages
            # Send Messages (2048) + Read Message History (65536) + View Channel (1024) = 68608
            permissions = 68608

            # Generate invite link
            invite_url = f"https://discord.com/api/oauth2/authorize?client_id={client_id}&permissions={permissions}&scope=bot"

            return jsonify({
                "status": "success",
                "bot_name": bot_name,
                "client_id": client_id,
                "invite_url": invite_url,
                "permissions": {
                    "value": permissions,
                    "description": "Send Messages, Read Message History, View Channel"
                },
                "instructions": "Click the invite URL to add the bot to your Discord server. Only users with administrator permissions can create API keys for this server.",
                "security_note": "API keys can only be created via Discord bot command and require administrator permissions",
                "logging_info": f"All API usage will be logged to channel ID: {LOG_CHANNEL_ID}"
            })
        else:
            return jsonify({
                "error": "Failed to get bot information from Discord API",
                "status": "discord_api_error",
                "response_code": response.status_code
            }), 500

    except Exception as e:
        return jsonify({
            "error": f"Error generating invite link: {str(e)}",
            "status": "server_error"
        }), 500


@app.route('/test-log')
def test_log():
    """Test endpoint to verify logging functionality"""
    success = send_usage_log(
        api_key="TEST_KEY",
        endpoint_type="GET",
        user_email="test@example.com",
        source_url="https://test.example.com",
        status="test"
    )

    return jsonify({
        "status": "success" if success else "failed",
        "message": "Test log sent" if success else "Failed to send test log",
        "log_channel": LOG_CHANNEL_ID
    })


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
