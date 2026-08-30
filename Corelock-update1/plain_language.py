"""
CoreLock - Traductor a Lenguaje Simple
==========================================
Convierte las alertas técnicas de CoreLock en explicaciones que
cualquier persona entiende, sin importar si sabe de seguridad o no.

No reemplaza el detalle técnico (que sigue disponible en cada log),
lo complementa con una capa de "qué pasó, por qué importa, y qué se hizo".
"""

# Cada entrada: (palabras clave a buscar en las razones técnicas,
#                qué pasó en criollo, por qué es peligroso)
EXPLANATIONS = [
    (
        ["minero conocido", "nombre de proceso coincide con minero"],
        "Un programa de minería de criptomonedas se estaba ejecutando escondido en tu PC.",
        "Estos programas usan tu procesador al máximo sin que lo notes, generando dinero para "
        "otra persona mientras tu PC se calienta, se pone lenta y gasta más luz.",
    ),
    (
        ["se hace pasar por proceso de sistema", "disfrazado"],
        "Un programa se estaba haciendo pasar por un proceso normal de Windows para no llamar la atención.",
        "Es una técnica clásica de malware: usar un nombre como 'svchost.exe' para que, si mirás "
        "el Administrador de Tareas, todo parezca normal.",
    ),
    (
        ["cpu sostenida"],
        "Un programa estuvo usando tu procesador al máximo durante mucho tiempo, sin ninguna razón aparente.",
        "Esto es típico de mineros de criptomonedas ocultos o de malware haciendo tareas pesadas "
        "en segundo plano sin que lo pediste.",
    ),
    (
        ["puerto riesgoso", "puerto sospechoso"],
        "Un programa intentó conectarse a un tipo de servidor que suelen usar los atacantes para "
        "controlar computadoras infectadas.",
        "Este tipo de conexión se usa para que alguien controle tu PC de forma remota, o para "
        "robar información sin que te des cuenta.",
    ),
    (
        ["patrón de escaneo", "ips distintas"],
        "Un programa se conectó a muchísimas direcciones distintas de internet en muy poco tiempo.",
        "Esto es lo que hace el malware cuando busca otras computadoras para infectar, o cuando "
        "envía tus datos a varios servidores para tapar el rastro.",
    ),
    (
        ["señuelo", "canary"],
        "Detectamos actividad que coincide exactamente con cómo actúa un ransomware.",
        "Un ransomware cifra tus archivos (fotos, documentos, todo) y después pide dinero para "
        "'devolvértelos'. Lo agarramos apenas empezó a tocar los archivos.",
    ),
    (
        ["extensión típica de ransomware", "extensión de ransomware"],
        "Se encontraron archivos con una extensión que usan los virus que secuestran archivos.",
        "Si tus archivos terminan en algo como '.locked' o '.encrypted', normalmente significa "
        "que ya no podés abrirlos sin pagarle a un atacante.",
    ),
    (
        ["cifrado masivo"],
        "Muchísimos archivos se estaban modificando al mismo tiempo, muy rápido.",
        "Ningún programa normal hace esto. Es la señal más clara de un ransomware cifrando tu "
        "disco en este mismo momento.",
    ),
    (
        ["robo de cookies", "cookies/credenciales"],
        "Un programa que no es tu navegador intentó leer el archivo donde se guardan tus sesiones iniciadas.",
        "Si alguien roba ese archivo, puede entrar a tus cuentas (redes, correo, etc.) sin "
        "necesitar tu contraseña, mientras tu sesión siga activa.",
    ),
    (
        ["motores antivirus", "malware confirmado"],
        "Un archivo que descargaste fue verificado contra decenas de antivirus reales, y varios "
        "coincidieron en que es malicioso.",
        "No es una sospecha nuestra: es el veredicto de motores antivirus profesionales "
        "(Kaspersky, Windows Defender, ESET, etc.) mirando ese mismo archivo.",
    ),
    (
        ["token", "discord", "steam"],
        "Un programa intentó acceder a los archivos donde se guardan tus sesiones de Discord o Steam.",
        "Robar estos archivos permite que alguien use tu cuenta sin tu contraseña -- a veces se "
        "usa después para estafar a tus contactos.",
    ),
    (
        ["autorun", "disfrazado de carpeta", "oculto+sistema"],
        "Se detectó un archivo sospechoso apenas conectaste un USB.",
        "Es una forma clásica de propagar virus entre computadoras: el USB ejecuta algo solo, "
        "o un ícono de carpeta en realidad es un programa.",
    ),
    (
        ["acceso directo (.lnk)"],
        "Se encontró un acceso directo sospechoso en la raíz de un USB.",
        "Algunos accesos directos maliciosos abren un programa oculto en vez de una carpeta real "
        "cuando hacés doble clic.",
    ),
]

ACTION_EXPLANATIONS = {
    "proceso terminado": "CoreLock cerró ese programa de inmediato.",
    "archivo en cuarentena": "CoreLock movió ese archivo a una carpeta aislada donde no puede ejecutarse ni hacer daño.",
    "ip bloqueada": "CoreLock bloqueó esa conexión en el firewall de Windows para que no pueda volver a comunicarse.",
    "bloqueado por red de seguridad": (
        "CoreLock decidió NO actuar automáticamente porque el objetivo era un proceso protegido "
        "del sistema -- conviene que lo revises vos manualmente."
    ),
}


def explain(reasons_text: str, action_taken: str = None) -> str:
    """Devuelve una explicación en lenguaje simple para un conjunto de
    razones técnicas (el texto que ya arma cada detector en 'Razones')."""
    if not reasons_text:
        return ""

    reasons_lower = reasons_text.lower()

    for keywords, what_happened, why_it_matters in EXPLANATIONS:
        if any(kw in reasons_lower for kw in keywords):
            explanation = f"🗣  En palabras simples: {what_happened} {why_it_matters}"
            if action_taken:
                action_lower = action_taken.lower()
                for key, action_text in ACTION_EXPLANATIONS.items():
                    if key in action_lower:
                        explanation += f" {action_text}"
                        break
            return explanation

    # Fallback genérico si ninguna razón conocida coincide
    explanation = f"🗣  En palabras simples: se detectó un comportamiento fuera de lo normal ({reasons_text})."
    if action_taken:
        explanation += " CoreLock tomó una acción automática para protegerte."
    return explanation


def print_explanation(reasons_text: str, action_taken: str = None):
    text = explain(reasons_text, action_taken)
    if text:
        print(f"\033[96m{text}\033[0m")
