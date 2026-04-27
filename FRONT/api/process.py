# FRONT/api/process.py
from http.server import BaseHTTPRequestHandler
import json
from .encryption import encrypt_file # Ajusta el import según tu lógica

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)

        # Aquí ejecutas tu lógica de criptografía que antes hacías con spawn
        # resultado = tu_funcion(data['archivo'])

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {"status": "success", "data": "archivo_cifrado_aqui"}
        self.wfile.write(json.dumps(response).encode())