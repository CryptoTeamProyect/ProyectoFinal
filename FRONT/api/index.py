from http.server import BaseHTTPRequestHandler
import json
# Aquí puedes importar tus algoritmos
# import encryption 

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Esta ruta responde a /api/index (o /api/vault/status si adaptas la ruta)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        # Aquí llamas a tus funciones de criptografía para armar la respuesta
        respuesta = {
            "status": "online",
            "mensaje": "¡La API de Python ya está conectada al Bóveda Digital!"
        }
        
        self.wfile.write(json.dumps(respuesta).encode('utf-8'))
        return