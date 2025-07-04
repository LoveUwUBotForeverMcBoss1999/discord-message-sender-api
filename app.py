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


def get_discord_username(user_id, bot_token):
    """
    Get Discord username from user ID
    Returns (username, error_message)
    """
    try:
        url = f"https://discord.com/api/v9/users/{user_id}"
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            user_data = response.json()
            username = user_data.get('username', 'Unknown')
            return username, None
        elif response.status_code == 404:
            return None, "User not found"
        elif response.status_code == 403:
            return None, "Bot lacks permission to fetch user data"
        else:
            return None, f"Discord API error: {response.status_code}"

    except Exception as e:
        return None, f"Error fetching username: {str(e)}"


# 2. Update the send_discord_message function (replace the existing one):

def send_discord_message(email, message, bot_token, channel_id, source_info=None, discord_id=None):
    # Format message - replace \ with actual line breaks
    formatted_message = message.replace('\\', '\n')

    # Add source info for security logging
    source_text = ""
    if source_info:
        source_text = f"\n🔗 **Source:** {source_info}"

    # Handle Discord ID and username
    discord_info = ""
    if discord_id:
        username, error = get_discord_username(discord_id, bot_token)
        if username:
            discord_info = f"\n🔴 **Username & ID:** {username} ({discord_id})"
        else:
            # Show ID even if username fetch failed
            discord_info = f"\n🔴 **Username & ID:** Unknown ({discord_id}) - {error}"

    url = f"https://discord.com/api/v9/channels/{channel_id}/messages"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }

    # If message is short enough, use embed description (4096 char limit)
    if len(formatted_message) <= 3600:  # Leave buffer for source info and discord info
        embed = {
            "title": "📧 New Message",
            "description": f"**📧 Email:** {email}{discord_info}\n\n**💬 Message:**\n{formatted_message}{source_text}",
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
                "description": f"**📧 Email:** {email}{discord_info}\n\n**💬 Message:** (Long message - sent in parts){source_text}",
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
    discord_id = data.get('discord_id')  # Add this line to get discord_id from JSON
    success = send_discord_message(email, message, bot_token, channel_id, source_info, discord_id)

    if success:
        # Log successful usage
        send_usage_log(key, "POST", user_email=email, source_url=source_info, status="success")

        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": email,
            "discord_id": discord_id,  # Add this line
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


@app.route('/api/<key>/email-<email>/message-<path:message>/id-<discord_id>')
def send_message_get_with_id(key, email, message, discord_id):
    """GET endpoint with Discord ID, URL authentication, owner verification, and logging"""

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

    # Decode URL-encoded message, email, and discord_id
    decoded_message = unquote(message)
    decoded_email = unquote(email)
    decoded_discord_id = unquote(discord_id)

    # Additional decoding to handle double encoding
    decoded_email = unquote(decoded_email)
    decoded_message = unquote(decoded_message)
    decoded_discord_id = unquote(decoded_discord_id)

    print(f"Original email: {email}")
    print(f"Decoded email: {decoded_email}")
    print(f"Original message: {message}")
    print(f"Decoded message: {decoded_message}")
    print(f"Original discord_id: {discord_id}")
    print(f"Decoded discord_id: {decoded_discord_id}")

    # Validate email format
    if not validate_email(decoded_email):
        send_usage_log(key, "GET", user_email=decoded_email, source_url=source_info, status="invalid_email")
        return jsonify({
            "error": "Invalid email format. Email must be in format: name@domain.com",
            "status": "bad_request",
            "received_email": decoded_email
        }), 400

    # Validate Discord ID format (should be numeric)
    if not decoded_discord_id.isdigit():
        send_usage_log(key, "GET", user_email=decoded_email, source_url=source_info, status="invalid_discord_id")
        return jsonify({
            "error": "Invalid Discord ID format. Discord ID must be numeric.",
            "status": "bad_request",
            "received_discord_id": decoded_discord_id
        }), 400

    # Send message to Discord with Discord ID
    success = send_discord_message(decoded_email, decoded_message, bot_token, channel_id, source_info, decoded_discord_id)

    if success:
        # Log successful usage
        send_usage_log(key, "GET", user_email=decoded_email, source_url=source_info, status="success")

        return jsonify({
            "status": "success",
            "message": "Message sent to Discord",
            "email": decoded_email,
            "discord_id": decoded_discord_id,
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


@app.route('/keys/<key>/info', methods=['GET'])
def get_key_info(key):
    """Get information about a specific key with security validation and URL authorization"""

    # Get origin and referer from headers
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    source_info = origin or referer or "Unknown"

    # 🔐 CRITICAL: Validate URL access first - this was missing!
    is_valid, error_msg = validate_url_access(key, origin, referer)
    if not is_valid:
        # Log unauthorized attempt
        send_usage_log(key, "GET", source_url=source_info, status="unauthorized")
        return jsonify({
            "error": error_msg,
            "status": "unauthorized",
            "security_note": "Request must come from authorized website"
        }), 403

    keys_data = load_keys()
    valid_keys = keys_data.get("keys", {})

    if key not in valid_keys:
        # Log invalid key attempt
        send_usage_log(key, "GET", source_url=source_info, status="invalid_key")
        return jsonify({
            "error": "Invalid API key",
            "status": "unauthorized"
        }), 401

    key_config = valid_keys[key]

    # Get Discord bot token for validation
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        send_usage_log(key, "GET", source_url=source_info, status="token_error")
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

    # 🔐 SECURITY CHECK: Verify API owner has admin permissions
    if not has_admin:
        send_usage_log(key, "GET", source_url=source_info, status="permission_denied")
        return jsonify({
            "error": f"API owner does not have administrator permissions in server: {admin_error}",
            "status": "permission_denied",
            "owner_id": owner_id,
            "server_id": server_id,
            "security_note": "Only users with administrator permissions can access API key info"
        }), 403

    # Log successful access
    send_usage_log(key, "GET", source_url=source_info, status="success")

    # Build access_status object - only include admin_check_error if there's an actual error
    access_status = {
        "server_access": server_access,
        "channel_access": channel_access,
        "owner_has_admin": has_admin
    }

    # Only add admin_check_error if there's actually an error
    if admin_error:
        access_status["admin_check_error"] = admin_error

    return jsonify({
        "key": key,
        "owner_id": owner_id,
        "config": key_config,
        "access_status": access_status,
        "security_status": "SECURE" if (server_access and channel_access and has_admin) else "INSECURE",
        "logging": {
            "enabled": True,
            "log_channel": LOG_CHANNEL_ID
        },
        "source": source_info,
        "security_verified": "Request authorized from registered URL and owner has admin permissions"
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


@app.route('/main')
def main_page():
    """The API Main Page"""
    try:
        with open('main.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content, 200, {'Content-Type': 'text/html; charset=utf-8'}
    except FileNotFoundError:
        return jsonify({
            "error": "Main page not found",
            "status": "file_not_found"
        }), 404
    except Exception as e:
        return jsonify({
            "error": f"Error loading documentation: {str(e)}",
            "status": "server_error"
        }), 500


@app.route('/api/<key>/server-info', methods=['GET'])
def get_server_info(key):
    """Get Discord server information with URL authentication, owner verification, and invite link"""

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

    if key not in valid_keys:
        send_usage_log(key, "GET", source_url=source_info, status="invalid_key")
        return jsonify({
            "error": "Invalid API key",
            "status": "unauthorized"
        }), 401

    # Get key configuration
    key_config = valid_keys[key]
    server_id = key_config.get("server_id")
    owner_id = key_config.get("owner_id")

    if not server_id or not owner_id:
        send_usage_log(key, "GET", source_url=source_info, status="config_error")
        return jsonify({
            "error": "Key configuration incomplete - missing server_id or owner_id",
            "status": "server_error"
        }), 500

    # Get Discord bot token from environment
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

    # Security check: Verify API owner has admin permissions in the server
    has_admin, admin_error = check_user_admin_permissions(owner_id, server_id, bot_token)
    if not has_admin:
        send_usage_log(key, "GET", source_url=source_info, status="permission_denied")
        return jsonify({
            "error": f"API owner does not have administrator permissions in server: {admin_error}",
            "status": "permission_denied",
            "owner_id": owner_id,
            "server_id": server_id,
            "security_note": "Only users with administrator permissions can access server info"
        }), 403

    try:
        # Get server information
        guild_url = f"https://discord.com/api/v9/guilds/{server_id}?with_counts=true"
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }

        response = requests.get(guild_url, headers=headers)

        if response.status_code == 200:
            guild_data = response.json()

            # Extract server information
            server_info = {
                "server_name": guild_data.get("name", "Unknown"),
                "server_description": guild_data.get("description", None),
                "server_member_count": guild_data.get("approximate_member_count", 0),
                "server_online_member_count": guild_data.get("approximate_presence_count", 0),
                "server_icon_url": None,
                "server_banner_url": None,
                "server_id": server_id,
                "owner_id": guild_data.get("owner_id"),
                "verification_level": guild_data.get("verification_level"),
                "created_at": guild_data.get("id"),  # Can calculate creation date from ID
                "features": guild_data.get("features", []),
                "invite_links": []  # Initialize invite links array
            }

            # Build icon URL if icon exists
            icon_hash = guild_data.get("icon")
            if icon_hash:
                server_info[
                    "server_icon_url"] = f"https://cdn.discordapp.com/icons/{server_id}/{icon_hash}.png?size=512"

            # Build banner URL if banner exists
            banner_hash = guild_data.get("banner")
            if banner_hash:
                server_info[
                    "server_banner_url"] = f"https://cdn.discordapp.com/banners/{server_id}/{banner_hash}.png?size=1024"

            # Get server invite links
            try:
                invites_url = f"https://discord.com/api/v9/guilds/{server_id}/invites"
                invites_response = requests.get(invites_url, headers=headers)

                if invites_response.status_code == 200:
                    invites_data = invites_response.json()

                    # Process invite links and extract useful information
                    for invite in invites_data:
                        invite_info = {
                            "code": invite.get("code"),
                            "url": f"https://discord.gg/{invite.get('code')}",
                            "channel_name": invite.get("channel", {}).get("name", "Unknown"),
                            "channel_id": invite.get("channel", {}).get("id"),
                            "inviter": None,
                            "expires_at": invite.get("expires_at"),
                            "max_uses": invite.get("max_uses"),
                            "uses": invite.get("uses", 0),
                            "temporary": invite.get("temporary", False),
                            "created_at": invite.get("created_at")
                        }

                        # Get inviter information if available
                        inviter_data = invite.get("inviter")
                        if inviter_data:
                            invite_info["inviter"] = {
                                "username": inviter_data.get("username"),
                                "id": inviter_data.get("id"),
                                "discriminator": inviter_data.get("discriminator")
                            }

                        server_info["invite_links"].append(invite_info)

                elif invites_response.status_code == 403:
                    # Bot doesn't have permission to view invites
                    server_info["invite_links_error"] = "Bot lacks permission to view server invites"

                else:
                    server_info["invite_links_error"] = f"Failed to fetch invites: {invites_response.status_code}"

            except Exception as invite_error:
                server_info["invite_links_error"] = f"Error fetching invites: {str(invite_error)}"

            # Try to create a new invite link if bot has permission
            try:
                # Find a general text channel to create invite for
                channels_url = f"https://discord.com/api/v9/guilds/{server_id}/channels"
                channels_response = requests.get(channels_url, headers=headers)

                if channels_response.status_code == 200:
                    channels_data = channels_response.json()

                    # Find first text channel where bot can create invite
                    general_channel = None
                    for channel in channels_data:
                        if channel.get("type") == 0:  # Text channel
                            general_channel = channel.get("id")
                            break

                    if general_channel:
                        # Try to create a new invite
                        create_invite_url = f"https://discord.com/api/v9/channels/{general_channel}/invites"
                        invite_payload = {
                            "max_age": 86400,  # 24 hours
                            "max_uses": 0,  # No limit
                            "temporary": False,
                            "unique": True
                        }

                        create_response = requests.post(create_invite_url, json=invite_payload, headers=headers)

                        if create_response.status_code == 200:
                            new_invite = create_response.json()
                            server_info["generated_invite"] = {
                                "code": new_invite.get("code"),
                                "url": f"https://discord.gg/{new_invite.get('code')}",
                                "expires_at": new_invite.get("expires_at"),
                                "channel_name": new_invite.get("channel", {}).get("name"),
                                "note": "Freshly generated invite link (24h expiry)"
                            }
                        else:
                            server_info[
                                "generated_invite_error"] = f"Failed to create new invite: {create_response.status_code}"

            except Exception as create_error:
                server_info["generated_invite_error"] = f"Error creating invite: {str(create_error)}"

            # Add summary of invite information
            server_info["invite_summary"] = {
                "total_invites": len(server_info["invite_links"]),
                "has_permanent_invites": any(invite.get("max_uses") == 0 and invite.get("expires_at") is None
                                             for invite in server_info["invite_links"]),
                "has_generated_invite": "generated_invite" in server_info
            }

            # Log successful usage
            send_usage_log(key, "GET", source_url=source_info, status="success")

            return jsonify({
                "status": "success",
                "server_info": server_info,
                "source": source_info,
                "security_verified": "API owner has administrator permissions"
            })

        elif response.status_code == 403:
            send_usage_log(key, "GET", source_url=source_info, status="discord_permission_error")
            return jsonify({
                "error": "Bot lacks permissions to access server information",
                "status": "discord_permission_error",
                "server_id": server_id
            }), 403

        elif response.status_code == 404:
            send_usage_log(key, "GET", source_url=source_info, status="server_not_found")
            return jsonify({
                "error": "Server not found or bot is not in the server",
                "status": "server_not_found",
                "server_id": server_id
            }), 404

        else:
            send_usage_log(key, "GET", source_url=source_info, status="discord_api_error")
            return jsonify({
                "error": f"Discord API error: {response.status_code}",
                "status": "discord_api_error",
                "response_code": response.status_code
            }), 500

    except Exception as e:
        send_usage_log(key, "GET", source_url=source_info, status="server_error")
        return jsonify({
            "error": f"Error fetching server information: {str(e)}",
            "status": "server_error"
        }), 500

@app.errorhandler(404)
def not_found_error(e):
    return jsonify({
        "error": "Not Found",
        "status": "not_found"
    }), 404



if __name__ == '__main__':
    app.run(debug=True)
