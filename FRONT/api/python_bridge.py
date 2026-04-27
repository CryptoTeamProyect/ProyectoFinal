from http.server import BaseHTTPRequestHandler
import json
import sys
import io
# Importamos tu lógica original
import encryption 

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        params = json.loads(post_data)
        args = params.get('args', [])

        # Capturamos lo que tus scripts imprimirían en la consola (stdout)
        stdout_capture = io.StringIO()
        sys.stdout = stdout_capture
        
        try:
            # Aquí es donde llamas a la función principal de tu encryption.py
            # pasando los argumentos que recibiste
            # Ejemplo: encryption.main(args)
            encryption.main(args) 
            status = 200
            output = stdout_capture.getvalue()
            error = ""
        except Exception as e:
            status = 500
            output = ""
            error = str(e)
        finally:
            sys.stdout = sys.__stdout__

        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        self.wfile.write(json.dumps({
            "stdout": output,
            "stderr": error
        }).encode())