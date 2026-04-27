from http.server import BaseHTTPRequestHandler
import json
import sys
import io
import os

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Configuración de lectura de datos
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        params = json.loads(post_data)
        args = params.get('args', [])

        # 2. Preparar la captura de salida (stdout)
        # Esto atrapa los 'print' de tus otros scripts para enviarlos al frontend
        stdout_capture = io.StringIO()
        sys.stdout = stdout_capture
        stderr_output = ""
        
        try:
            # 3. Ajuste de rutas dinámico
            # Agregamos la carpeta actual al PATH para que 'import encryption' funcione en Vercel
            current_dir = os.path.dirname(os.path.abspath(__file__))
            if current_dir not in sys.path:
                sys.path.append(current_dir)
            
            # 4. Importar tu lógica original
            import encryption
            
            # 5. Ejecución
            # Asumimos que encryption.py tiene una función main(args)
            # Si tu función se llama diferente, cambia 'main' por el nombre correcto
            if hasattr(encryption, 'main'):
                encryption.main(args)
            else:
                print("Error: No se encontró la función 'main' en encryption.py")
                
        except Exception as e:
            # Si algo truena, lo capturamos para que no de Error 500
            stderr_output = f"Error en el puente Python: {str(e)}"
        finally:
            # Regresamos el stdout a la normalidad
            sys.stdout = sys.__stdout__

        # 6. Respuesta al Frontend
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response_data = {
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_output,
            "status": "success" if not stderr_output else "error"
        }
        
        self.wfile.write(json.dumps(response_data).encode())