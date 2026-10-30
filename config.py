DB_CONFIG = {
    "host": "127.0.0.1",
    "port": "5432",
    "database": "salsamentaria",
    "user": "postgres",
    "password": "123456",
}

# Correo saliente (para enviar facturas a los clientes).
# Con Gmail: activar verificación en 2 pasos y crear una "contraseña de
# aplicación" (https://myaccount.google.com/apppasswords). Esa clave de 16
# letras va en CORREO_CLAVE, NO la contraseña normal de la cuenta.
# Lo ideal es definir estos valores como variables de entorno.
import os

EMAIL_CONFIG = {
    "host": os.environ.get("CORREO_HOST", "smtp.gmail.com"),
    "port": int(os.environ.get("CORREO_PUERTO", "587")),
    "user": os.environ.get("CORREO_USUARIO", "urregojulianricardoinsecaldas@gmail.com"),
    "password": os.environ.get("CORREO_CLAVE", "riko wcjj xlrx zchx"),
    "nombre": "Salsamentaria",
}
