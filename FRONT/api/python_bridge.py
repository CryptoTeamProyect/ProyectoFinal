from http.server import BaseHTTPRequestHandler
import json
import sys
import io
import os
import traceback

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        params = json.loads(post_data)
        args = params.get('args', [])

        stdout_capture = io.StringIO()
        sys.stdout = stdout_capture
        stderr_output = ""
        
        try:
            # Agregamos la ruta actual al path
            current_dir = os.path.dirname(os.path.abspath(__file__))
            if current_dir not in sys.path:
                sys.path.append(current_dir)
            
            # Intentamos importar
            import encryption
            
            # Ejecutamos
            encryption.main(args)
            status_code = 200
        except Exception as e:
            # Si falla, capturamos TODO el rastro del error
            status_code = 200 # Mantenemos 200 para que el JSON llegue bien
            stderr_output = f"ERROR EN PYTHON:\n{traceback.format_exc()}"
        finally:
            sys.stdout = sys.__stdout__

        # Mandamos la respuesta siempre como JSON válido
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response_data = {
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_output
        }
        self.wfile.write(json.dumps(response_data).encode())