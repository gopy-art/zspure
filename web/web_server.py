import http.server
import subprocess
import urllib.parse
import os

"""
This file will run a web server that serve the .php files base on the url
it will listen in localhost on port 8000
"""
class PHPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == '/' or path == '':
            path = '/index.php'

        if path.endswith('/'):
            path = path + 'index.php'

        if path.endswith('.php'):
            php_file = path.lstrip('/')

            if not os.path.exists(php_file):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'File not found')
                return
            
            result = subprocess.run(
                ['php', php_file],
                capture_output=True,
                text=True
            )
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(result.stdout.encode())
        else:
            super().do_GET()

if __name__ == '__main__':
    with http.server.HTTPServer(('localhost', 8000), PHPHandler) as server:
        print("Server running on http://localhost:8000")
        server.serve_forever()