from http.server import BaseHTTPRequestHandler
import json
# Importa aquí tus funciones de encryption si las tienes en otro archivo .py
# from .encryption import generar_claves 

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Leer los datos que mandas desde el frontend
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)

        # 2. Ejecutar tu lógica (por ejemplo, generar una clave)
        # resultado = generar_claves(data['user'])
        resultado = {"mensaje": "¡Logramos ejecutar Python en Vercel!"}

        # 3. Responder al frontend
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(resultado).encode())