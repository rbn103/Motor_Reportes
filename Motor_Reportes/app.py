import sys
import os

# Asegurar que el directorio actual está en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.join(current_dir, 'backend'))

from flask import Flask, render_template, request, jsonify
from lexer import AnalizadorLexicoVulnerabilidades
from parser import AnalizadorSintacticoVulnerabilidades
from semantic import AnalizadorSemanticoVulnerabilidades
from output_gen import GeneradorMitigacion

app = Flask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static"
)

# Inicialización global de las clases del motor para que estén disponibles en memoria
analizador_lexico = AnalizadorLexicoVulnerabilidades()
analizador_sintactico = AnalizadorSintacticoVulnerabilidades()
analizador_semantico = AnalizadorSemanticoVulnerabilidades()
generador_mitigacion = GeneradorMitigacion()


@app.route('/')
def index():
    """Sirve la interfaz gráfica web estructurada en el frontend"""
    return render_template('index.html')


@app.route('/analizar', methods=['POST'])
def analizar_reporte():
    """Punto de comunicación asíncrona donde llega el reporte de vulnerabilidades crudo"""
    datos_recibidos = request.get_json()
    texto_crudo = datos_recibidos.get('text', '')

    if not texto_crudo.strip():
        return jsonify({"error": "El reporte enviado no contiene texto para procesar"}), 400

    # EJECUCIÓN SECUENCIAL DEL PIPELINE DEL MOTOR (FASES DEL COMPILADOR)
    tokens = analizador_lexico.tokenizar(texto_crudo)
    estructura = analizador_sintactico.analizar_sintaxis(tokens)
    analisis_semantico = analizador_semantico.evaluar_semantica(estructura)
    acciones_mitigacion = generador_mitigacion.generar_acciones_automatizadas(estructura, analisis_semantico)

    # Retornamos el paquete completo en formato JSON estructurado hacia JavaScript
    return jsonify({
        "tokens": tokens,
        "estructura": estructura,
        "analisis_semantico": analisis_semantico,
        "acciones_mitigacion": acciones_mitigacion
    })


# =========================================================================
# RUTA DETOX: MÓDULO INTERACTIVO CON ENLACE DE BYTES MIME SEGUROS
# =========================================================================
@app.route('/notificar', methods=['POST'])
def notificar_encargado():
    """Recibe los datos del formulario y credenciales para ejecutar la alerta"""
    try:
        data = request.get_json()

        # 1. Recuperamos las credenciales dinámicas
        correo_emisor = data.get('correo_emisor', '').strip()
        password_emisor = data.get('password_emisor', '').strip()

        # 2. Recuperamos el incidente
        correo_destino = data.get('correo', '').strip()
        asunto = data.get('asunto', '').strip()
        mensaje = data.get('mensaje', '').strip()

        if not correo_emisor or not password_emisor or not correo_destino or not asunto or not mensaje:
            return jsonify({"status": "error", "message": "Credenciales o campos obligatorios faltantes."}), 400

        # Enviamos las cadenas directas al backend modular
        resultado = generador_mitigacion.enviar_notificacion_gmail(
            correo_emisor, password_emisor, correo_destino, asunto, mensaje
        )
        return jsonify(resultado)

    except Exception as e:
        return jsonify({"status": "error", "message": f"Fallo de orquestación en app.py: {str(e)}"}), 500


if __name__ == '__main__':
    # Habilitamos el modo de depuración para desarrollo ágil en equipo
    app.run(debug=True)
