def get_server_info_from_channel(channel_id, bot_token):
    """Get server information from a channel ID"""
    url = f"https://discord.com/api/v9/channels/{channel_id}"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            channel_data = response.json()
            return {
                "success": True,
                "channel_id": channel_data.get("id"),
                "guild_id": channel_data.get("guild_id"),
                "channel_name": channel_data.get("name"),
                "channel_type": channel_data.get("type")
            }
        else:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}",
                "response": response.text
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.route('/debug-channel/<channel_id>')
def debug_channel_info(channel_id):
    """Debug endpoint to get channel and server info"""
    bot_token = os.getenv('DISCORD_BOT_TOKEN') or os.getenv('discord_bot_token')
    if not bot_token:
        return jsonify({"error": "No bot token configured"}), 500
    
    channel_info = get_server_info_from_channel(channel_id, bot_token)
    return jsonify(channel_info)
