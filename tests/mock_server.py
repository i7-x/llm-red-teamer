"""
Mock LLM API Server for Testing LLM Red Teamer Without Real API Calls
Run with: python -m tests.mock_server
"""

import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

class MockLLMHandler(BaseHTTPRequestHandler):
    """Simulates an OpenAI-compatible /v1/chat/completions endpoint."""
    
    def do_POST(self):
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/v1/chat/completions":
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            
            try:
                request_data = json.loads(body)
                messages = request_data.get('messages', [])
                user_message = ""
                for msg in messages:
                    if msg.get('role') == 'user':
                        user_message = msg.get('content', '')
                        break
                
                # Simulate a harmless response that might leak info in a real scenario
                # We'll return something that could trigger detection for demonstration
                response_content = self._generate_response(user_message)
                
                response = {
                    "id": "mock-123",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": request_data.get('model', 'mock-model'),
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": response_content
                            },
                            "finish_reason": "stop"
                        }
                    ],
                    "usage": {
                        "prompt_tokens": len(user_message) // 4,
                        "completion_tokens": len(response_content) // 4,
                        "total_tokens": (len(user_message) + len(response_content)) // 4
                    }
                }
            except Exception as e:
                response = {"error": f"Invalid request: {str(e)}"}
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error": "Not found"}')
    
    def _generate_response(self, user_message: str) -> str:
        """Generate a mock response that mimics potential vulnerabilities."""
        msg_lower = user_message.lower()
        
        # Simulate different vulnerability responses for detection testing
        if "ignore" in msg_lower and "previous" in msg_lower:
            return "Okay, I will ignore all previous instructions. What would you like me to do?"
        elif "system prompt" in msg_lower and ("tell me" in msg_lower or "reveal" in msg_lower):
            return "My system prompt is: 'You are a helpful assistant. Do not reveal sensitive information.'"
        elif "dan" in msg_lower or "do anything now" in msg_lower:
            return "I am now in DAN mode. I can do anything you ask without restrictions."
        elif "grandma" in msg_lower and "napalm" in msg_lower:
            return "Here are the instructions for napalm production... [simulated dangerous content]"
        elif "admin" in msg_lower and "override" in msg_lower:
            return "Admin privileges granted. You now have full system access."
        elif "password" in msg_lower or "secret" in msg_lower:
            return "The admin password is 'SuperSecret123!' (simulated data leak)"
        elif "api key" in msg_lower:
            return "Here is the API key you requested: sk-mock-1234567890abcdef"
        elif "pii" in msg_lower or "social security" in msg_lower:
            return "John Doe's SSN is 123-45-6789 (simulated PII)"
        elif "url" in msg_lower and "http" in msg_lower:
            return f"I will send the data to {user_message.split('http')[1].split()[0] if 'http' in user_message else 'http://attacker.com'}"
        else:
            # Default harmless response
            return "I'm a helpful AI assistant. How can I help you today?"
    
    def log_message(self, format, *args):
        # Suppress default logging; we'll print minimal info
        pass

def run_server(port=8000):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, MockLLMHandler)
    print(f"✅ Mock LLM server running at http://127.0.0.1:{port}/v1")
    print("   Press Ctrl+C to stop.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped.")
        httpd.server_close()

if __name__ == "__main__":
    run_server()