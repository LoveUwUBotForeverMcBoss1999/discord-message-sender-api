<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Discord API Tester</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            max-width: 600px;
            width: 100%;
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 2.5em;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: bold;
        }
        
        input, textarea, select {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e1e1;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.8);
        }
        
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #667eea;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.2);
        }
        
        textarea {
            min-height: 120px;
            resize: vertical;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
            margin-top: 10px;
        }
        
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .response {
            margin-top: 30px;
            padding: 20px;
            border-radius: 10px;
            display: none;
            animation: slideIn 0.5s ease;
        }
        
        .success {
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
        }
        
        .error {
            background: linear-gradient(135deg, #f44336, #da190b);
            color: white;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .note {
            background: rgba(102, 126, 234, 0.1);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
        }
        
        .url-preview {
            background: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: monospace;
            word-break: break-all;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Discord API Tester</h1>
        
        <div class="note">
            <strong>💡 Note:</strong> Use <code>\</code> in your message for line breaks. Example: "Hello\This is a new line"
        </div>
        
        <form id="apiForm">
            <div class="form-group">
                <label for="apiUrl">🌐 API Base URL:</label>
                <input type="url" id="apiUrl" value="https://discord-message-sender-api.vercel.app" required>
            </div>
            
            <div class="form-group">
                <label for="apiKey">🔑 API Key:</label>
                <select id="apiKey" required>
                    <option value="">Select API Key</option>
                    <option value="test-key-123">test-key-123</option>
                    <option value="customer-service-key">customer-service-key</option>
                    <option value="feedback-key-456">feedback-key-456</option>
                    <option value="support-key-789">support-key-789</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="email">📧 Email:</label>
                <input type="email" id="email" placeholder="user@example.com" required>
            </div>
            
            <div class="form-group">
                <label for="message">💬 Message:</label>
                <textarea id="message" placeholder="Enter your message here...\Use backslash for line breaks" required></textarea>
            </div>
            
            <button type="submit" class="btn">📤 Send Message</button>
        </form>
        
        <div class="url-preview" id="urlPreview"></div>
        
        <div id="response" class="response"></div>
    </div>

    <script>
        const form = document.getElementById('apiForm');
        const response = document.getElementById('response');
        const urlPreview = document.getElementById('urlPreview');
        const apiUrl = document.getElementById('apiUrl');
        const apiKey = document.getElementById('apiKey');
        const email = document.getElementById('email');
        const message = document.getElementById('message');

        // Update URL preview in real-time
        function updatePreview() {
            if (apiUrl.value && apiKey.value && email.value && message.value) {
                const encodedMessage = encodeURIComponent(message.value);
                const fullUrl = `${apiUrl.value}/api/${apiKey.value}/email-${email.value}/message-${encodedMessage}`;
                urlPreview.textContent = `Generated URL: ${fullUrl}`;
                urlPreview.style.display = 'block';
            } else {
                urlPreview.style.display = 'none';
            }
        }

        // Add event listeners for real-time preview
        [apiUrl, apiKey, email, message].forEach(input => {
            input.addEventListener('input', updatePreview);
        });

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const btn = form.querySelector('.btn');
            btn.textContent = '⏳ Sending...';
            btn.disabled = true;
            
            try {
                const encodedMessage = encodeURIComponent(message.value);
                const fullUrl = `${apiUrl.value}/api/${apiKey.value}/email-${email.value}/message-${encodedMessage}`;
                
                const res = await fetch(fullUrl);
                const data = await res.json();
                
                response.style.display = 'block';
                
                if (res.ok) {
                    response.className = 'response success';
                    response.innerHTML = `
                        <h3>✅ Success!</h3>
                        <p><strong>Status:</strong> ${data.status}</p>
                        <p><strong>Message:</strong> ${data.message}</p>
                        <p><strong>Email:</strong> ${data.email}</p>
                        <p><strong>Sent Message:</strong></p>
                        <pre>${data.sent_message}</pre>
                    `;
                } else {
                    response.className = 'response error';
                    response.innerHTML = `
                        <h3>❌ Error!</h3>
                        <p><strong>Status:</strong> ${data.status || 'Unknown'}</p>
                        <p><strong>Error:</strong> ${data.error || 'Unknown error occurred'}</p>
                    `;
                }
            } catch (error) {
                response.style.display = 'block';
                response.className = 'response error';
                response.innerHTML = `
                    <h3>❌ Network Error!</h3>
                    <p>Failed to connect to the API. Please check your URL and try again.</p>
                    <p><strong>Error:</strong> ${error.message}</p>
                `;
            }
            
            btn.textContent = '📤 Send Message';
            btn.disabled = false;
        });
    </script>
</body>
</html>
