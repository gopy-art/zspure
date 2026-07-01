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
        query = parsed.query

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
            
            env = os.environ.copy()
            if query:
                env['QUERY_STRING'] = query
            
            result = subprocess.run(
                ['php', php_file],
                capture_output=True,
                text=True,
                env=env
            )
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(result.stdout.encode())
        else:
            file_path = path.lstrip('/')
            
            possible_paths = [
                file_path,
                os.path.join('..', 'modules', file_path),
                os.path.join('..', file_path),
            ]
            
            found_path = None
            for possible in possible_paths:
                if os.path.exists(possible):
                    found_path = possible
                    break
            
            if found_path:
                if found_path.endswith('.png'):
                    content_type = 'image/png'
                elif found_path.endswith('.jpg') or found_path.endswith('.jpeg'):
                    content_type = 'image/jpeg'
                elif found_path.endswith('.gif'):
                    content_type = 'image/gif'
                elif found_path.endswith('.css'):
                    content_type = 'text/css'
                elif found_path.endswith('.js'):
                    content_type = 'application/javascript'
                elif found_path.endswith('.svg'):
                    content_type = 'image/svg+xml'
                else:
                    content_type = 'application/octet-stream'
                
                try:
                    with open(found_path, 'rb') as f:
                        self.send_response(200)
                        self.send_header('Content-type', content_type)
                        self.end_headers()
                        self.wfile.write(f.read())
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(str(e).encode())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'File not found')

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    with http.server.HTTPServer(('localhost', 8000), PHPHandler) as server:
        print("Server running on http://localhost:8000")
        server.serve_forever()