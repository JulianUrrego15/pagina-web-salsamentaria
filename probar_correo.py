# Prueba de correo, sin tocar la app.
# Ponlo en la misma carpeta que config.py y ejecútalo:  python probar_correo.py
import smtplib
import socket
from config import EMAIL_CONFIG

host = EMAIL_CONFIG["host"]
user = EMAIL_CONFIG["user"]
clave = EMAIL_CONFIG["password"]

print("Usuario:", user)
print("Largo de la clave:", len(clave.replace(" ", "")), "(una clave de aplicación de Gmail tiene 16 letras)\n")

for puerto in (587, 465):
    print("=" * 50)
    print("Probando", host, "puerto", puerto)
    try:
        socket.create_connection((host, puerto), timeout=10).close()
        print("  1) Puerto abierto: OK")
    except Exception as e:
        print("  1) No se pudo abrir el puerto:", repr(e))
        print("     -> Lo bloquea la red, el antivirus o el firewall.")
        continue

    try:
        if puerto == 465:
            s = smtplib.SMTP_SSL(host, puerto, timeout=20)
        else:
            s = smtplib.SMTP(host, puerto, timeout=20)
            s.ehlo()
            s.starttls()
            s.ehlo()
        print("  2) Conexión segura: OK")
        s.login(user, clave.replace(" ", ""))
        print("  3) Inicio de sesión: OK  ->  ¡esta configuración funciona!")
        s.quit()
        break
    except smtplib.SMTPAuthenticationError as e:
        print("  3) Gmail rechazó el usuario o la clave:", e.smtp_code)
        print("     -> Falta la contraseña de aplicación de 16 letras.")
        break
    except Exception as e:
        print("  2) Falló:", repr(e))
