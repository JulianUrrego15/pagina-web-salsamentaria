from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import psycopg2
from config import DB_CONFIG, EMAIL_CONFIG
from functools import wraps
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from datetime import date, timedelta
import hashlib
import re
import smtplib
from email.message import EmailMessage
import io
import os
import time
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

CENTAVOS = Decimal("0.01")

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    Fernet = None
    InvalidToken = Exception


app = Flask(__name__)


def cargar_clave_secreta():
    """
    Clave con la que Flask firma la sesión. Si fuera conocida, cualquiera
    podría fabricar una sesión y entrar sin contraseña. Se genera una
    aleatoria la primera vez y se guarda en secret_key.txt (no compartir).
    """
    desde_entorno = os.environ.get("FLASK_SECRET_KEY")
    if desde_entorno:
        return desde_entorno

    ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret_key.txt")

    if os.path.exists(ruta):
        with open(ruta, "r", encoding="utf-8") as archivo:
            clave = archivo.read().strip()
        if len(clave) >= 32:
            return clave

    clave = secrets.token_hex(32)
    with open(ruta, "w", encoding="utf-8") as archivo:
        archivo.write(clave)
    return clave


app.secret_key = cargar_clave_secreta()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=10),
)


def cargar_cifrador():
    """
    Cifrador para guardar la contraseña de los empleados de forma que el
    administrador pueda consultarla. La llave vive en clave_cifrado.key
    (fuera de la base de datos). Si se pierde, las contraseñas guardadas
    no se podrán ver, pero los empleados seguirán entrando normalmente.
    """
    if Fernet is None:
        print("AVISO: falta instalar 'cryptography' (pip install cryptography); "
              "no se podrán mostrar las contraseñas de los empleados.")
        return None

    llave = os.environ.get("CLAVE_CIFRADO")

    if not llave:
        ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clave_cifrado.key")

        if os.path.exists(ruta):
            with open(ruta, "r", encoding="utf-8") as archivo:
                llave = archivo.read().strip()
        else:
            llave = Fernet.generate_key().decode()
            with open(ruta, "w", encoding="utf-8") as archivo:
                archivo.write(llave)

    return Fernet(llave.encode())


CIFRADOR = cargar_cifrador()


def cifrar_clave(clave):
    if CIFRADOR is None:
        return None
    return CIFRADOR.encrypt(clave.encode("utf-8")).decode("utf-8")


def descifrar_clave(texto):
    if CIFRADOR is None or not texto:
        return None
    try:
        return CIFRADOR.decrypt(texto.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def obtener_conexion():
    return psycopg2.connect(**DB_CONFIG)


def preparar_seguridad():
    """
    Se ejecuta al iniciar la app (es seguro repetirlo):
    - agrega la columna usuarios.activo si no existe
    - cifra las contraseñas que todavía estén en texto plano
    - evita dos usuarios con el mismo nombre de usuario
    """
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute(
            "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS activo BOOLEAN NOT NULL DEFAULT TRUE"
        )
        cursor.execute(
            "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS clave_cifrada TEXT"
        )

        cursor.execute("SELECT cod_usu, clave FROM usuarios")

        for cod_usu, clave in cursor.fetchall():
            if not clave.startswith(("scrypt:", "pbkdf2:")):
                cursor.execute(
                    "UPDATE usuarios SET clave = %s WHERE cod_usu = %s",
                    (generate_password_hash(clave), cod_usu)
                )

        conexion.commit()

    except Exception:
        conexion.rollback()
        raise

    finally:
        cursor.close()
        conexion.close()

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS usuarios_usuario_unico ON usuarios (LOWER(usuario))"
        )
        conexion.commit()
    except Exception as error:
        conexion.rollback()
        print("NO SE PUDO CREAR EL ÍNDICE ÚNICO DE USUARIOS:", error)
    finally:
        cursor.close()
        conexion.close()


try:
    preparar_seguridad()
except Exception as error:
    print("NO SE PUDO PREPARAR LA SEGURIDAD DE USUARIOS:", error)


def preparar_esquema():
    """
    Se ejecuta al iniciar la app (es seguro repetirlo): crea lo necesario
    para anular ventas y registrar devoluciones.
    """
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("ALTER TABLE ventas ADD COLUMN IF NOT EXISTS motivo_anulacion TEXT")
        cursor.execute("ALTER TABLE ventas ADD COLUMN IF NOT EXISTS fecha_anulacion TIMESTAMP")
        cursor.execute("ALTER TABLE ventas ADD COLUMN IF NOT EXISTS cod_usu_anula INTEGER REFERENCES usuarios(cod_usu)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devoluciones (
                cod_dev SERIAL PRIMARY KEY,
                cod_ven INTEGER NOT NULL REFERENCES ventas(cod_ven),
                cod_usu INTEGER NOT NULL REFERENCES usuarios(cod_usu),
                fecha TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                motivo VARCHAR(200) NOT NULL,
                total_devuelto NUMERIC(10,2) NOT NULL DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detalle_devolucion (
                cod_det_dev SERIAL PRIMARY KEY,
                cod_dev INTEGER NOT NULL REFERENCES devoluciones(cod_dev) ON DELETE CASCADE,
                cod_detalle INTEGER NOT NULL REFERENCES detalle_venta(cod_detalle),
                cantidad INTEGER NOT NULL CHECK (cantidad > 0),
                valor NUMERIC(10,2) NOT NULL
            )
        """)

        conexion.commit()

    except Exception:
        conexion.rollback()
        raise

    finally:
        cursor.close()
        conexion.close()


try:
    preparar_esquema()
except Exception as error:
    print("NO SE PUDO PREPARAR LAS TABLAS DE DEVOLUCIONES:", error)


def sincronizar_stock_en(cursor, cod_prod):
    """Deja stock_en igual al stock_actual del producto."""
    cursor.execute("""
        INSERT INTO stock_en (cod_prod, cantidad_actual, stock_minimo)
        SELECT cod_prod, stock_actual, 5
        FROM productos
        WHERE cod_prod = %s
        ON CONFLICT (cod_prod)
        DO UPDATE SET cantidad_actual = EXCLUDED.cantidad_actual
    """, (cod_prod,))


def mover_stock(cursor, cod_prod, cantidad):
    """
    Suma (o resta, si es negativa) existencias de un producto.
    Al quedar en 0 el producto NO se desactiva: sigue activo y aparece
    en las alertas de bajo stock. Si estaba en 0 (o menos) y vuelve a
    tener existencias, se asegura de que quede 'Activo'. Un producto
    desactivado a mano con existencias no se reactiva solo.
    """
    cursor.execute("""
        UPDATE productos
        SET stock_actual = stock_actual + %s,
            estado = CASE
                WHEN stock_actual <= 0 AND stock_actual + %s > 0 THEN 'Activo'
                ELSE estado
            END
        WHERE cod_prod = %s
    """, (cantidad, cantidad, cod_prod))


def descontar_lotes(cursor, cod_prod, cantidad, cod_bod=None):
    """
    Descuenta de los lotes activos, primero el que vence antes (FIFO).
    Si se indica cod_bod, solo usa los lotes de esa bodega.
    Devuelve (lista de (cod_lote, cantidad_tomada), cantidad_que_no_se_pudo_cubrir).
    """
    consulta = """
        SELECT cod_lote, cantidad_disponible
        FROM lotes_producto
        WHERE cod_prod = %s
          AND estado = 'Activo'
          AND cantidad_disponible > 0
    """
    parametros = [cod_prod]

    if cod_bod is not None:
        consulta += " AND ubicacion_bodega = %s"
        parametros.append(cod_bod)

    consulta += """
        ORDER BY fecha_vencimiento ASC NULLS LAST, cod_lote ASC
        FOR UPDATE
    """

    cursor.execute(consulta, parametros)

    pendiente = cantidad
    tramos = []

    for cod_lote, disponible in cursor.fetchall():
        if pendiente == 0:
            break

        tomar = min(disponible, pendiente)

        cursor.execute("""
            UPDATE lotes_producto
            SET cantidad_disponible = cantidad_disponible - %s
            WHERE cod_lote = %s
        """, (tomar, cod_lote))

        tramos.append((cod_lote, tomar))
        pendiente -= tomar

    return tramos, pendiente


def consultar_bajo_stock(cursor):
    """Productos activos con existencias iguales o menores al mínimo."""
    cursor.execute("""
        SELECT
            p.nom_prod,
            p.stock_actual,
            COALESCE(se.stock_minimo, 5)
        FROM productos p
        LEFT JOIN stock_en se
            ON se.cod_prod = p.cod_prod
        WHERE p.estado = 'Activo'
          AND p.stock_actual <= COALESCE(se.stock_minimo, 5)
        ORDER BY p.stock_actual ASC, p.nom_prod ASC
    """)
    return cursor.fetchall()


def reconciliar_inventario():
    """
    Deja el inventario con una sola cifra de verdad: productos.stock_actual,
    que es la que usan el punto de venta y la facturación.

    - Si los lotes suman MÁS que stock_actual (algo que no puede ser), se
      descuenta el exceso de los lotes que primero vencen (como lo habría
      hecho una venta, FIFO).
    - stock_en se iguala a stock_actual para todos los productos.

    Es seguro repetirlo: si todo está cuadrado, no cambia nada.
    """
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT p.cod_prod, p.nom_prod, p.stock_actual,
                   COALESCE(SUM(l.cantidad_disponible), 0)
            FROM productos p
            LEFT JOIN lotes_producto l
                ON l.cod_prod = p.cod_prod
               AND l.estado = 'Activo'
            GROUP BY p.cod_prod, p.nom_prod, p.stock_actual
            HAVING COALESCE(SUM(l.cantidad_disponible), 0) > GREATEST(p.stock_actual, 0)
        """)

        for cod_prod, nombre, stock, en_lotes in cursor.fetchall():
            exceso = en_lotes - max(stock, 0)
            descontar_lotes(cursor, cod_prod, exceso)
            print(
                "INVENTARIO CORREGIDO:", nombre,
                "- stock", stock, "- lotes sumaban", en_lotes,
                "- se ajustaron", exceso, "unidad(es) de lotes."
            )

        cursor.execute("""
            INSERT INTO stock_en (cod_prod, cantidad_actual, stock_minimo)
            SELECT cod_prod, stock_actual, 5
            FROM productos
            ON CONFLICT (cod_prod)
            DO UPDATE SET cantidad_actual = EXCLUDED.cantidad_actual
        """)

        conexion.commit()

    except Exception:
        conexion.rollback()
        raise

    finally:
        cursor.close()
        conexion.close()


try:
    reconciliar_inventario()
except Exception as error:
    print("NO SE PUDO CUADRAR EL INVENTARIO:", error)


# Días de anticipación para avisar que una mercancía está por vencer.
DIAS_ALERTA_VENCIMIENTO = 7


def texto_vencimiento(dias):
    """Frase corta según los días que faltan para vencer."""
    if dias < 0:
        n = -dias
        return "Vencido hace " + str(n) + (" día" if n == 1 else " días")

    if dias == 0:
        return "Vence hoy"

    if dias == 1:
        return "Vence mañana"

    return "Vence en " + str(dias) + " días"


def consultar_lotes_por_vencer():
    """Lotes con existencias que vencen en DIAS_ALERTA_VENCIMIENTO días o menos (o ya vencidos)."""
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                p.nom_prod,
                l.lote,
                b.nom_bod,
                l.cantidad_disponible,
                l.fecha_vencimiento,
                (l.fecha_vencimiento - CURRENT_DATE) AS dias
            FROM lotes_producto l
            INNER JOIN productos p
                ON p.cod_prod = l.cod_prod
            INNER JOIN bodegas b
                ON b.cod_bod = l.ubicacion_bodega
            WHERE l.estado = 'Activo'
              AND p.estado = 'Activo'
              AND l.cantidad_disponible > 0
              AND l.fecha_vencimiento IS NOT NULL
              AND l.fecha_vencimiento <= CURRENT_DATE + %s
            ORDER BY l.fecha_vencimiento ASC, p.nom_prod ASC
        """, (DIAS_ALERTA_VENCIMIENTO,))

        return [
            {
                "producto": fila[0],
                "lote": fila[1],
                "bodega": fila[2],
                "cantidad": fila[3],
                "fecha": fila[4].strftime("%d/%m/%Y"),
                "dias": fila[5],
                "texto": texto_vencimiento(fila[5])
            }
            for fila in cursor.fetchall()
        ]

    finally:
        cursor.close()
        conexion.close()


@app.after_request
def agregar_alerta_vencimientos(respuesta):
    """
    Agrega a todas las pantallas (menos login y factura) la campana de
    vencimientos: aviso emergente + lista de lotes por vencer.
    Si algo falla, la página se muestra igual, solo sin la campana.
    """
    try:
        if (
            respuesta.status_code != 200
            or respuesta.mimetype != "text/html"
            or respuesta.direct_passthrough
            or "cod_usu" not in session
            or request.endpoint in ("login", "factura", "static")
        ):
            return respuesta

        lotes = consultar_lotes_por_vencer()

        if not lotes:
            return respuesta

        pagina = respuesta.get_data(as_text=True)

        if "</body>" not in pagina:
            return respuesta

        firma = hashlib.md5(
            repr([(l["producto"], l["lote"], l["fecha"], l["cantidad"]) for l in lotes])
            .encode("utf-8")
        ).hexdigest()

        alerta = render_template(
            "alerta_vencimientos.html",
            lotes=lotes,
            firma=firma,
            dias_alerta=DIAS_ALERTA_VENCIMIENTO
        )

        antes, _, despues = pagina.rpartition("</body>")
        respuesta.set_data(antes + alerta + "</body>" + despues)

    except Exception as error:
        print("NO SE PUDO AGREGAR LA ALERTA DE VENCIMIENTOS:", error)

    return respuesta


def aviso_entrada_por_vencer(fecha_texto, nombres):
    """Mensaje para mostrar al registrar una entrada que vence pronto (o None)."""
    try:
        fecha = date.fromisoformat(fecha_texto)
    except (TypeError, ValueError):
        return None

    dias = (fecha - date.today()).days

    if dias > DIAS_ALERTA_VENCIMIENTO:
        return None

    productos = ", ".join(nombres)
    if dias < 0:
        cuando = "venció hace " + str(-dias) + (" día" if dias == -1 else " días")
    else:
        cuando = texto_vencimiento(dias).lower()

    return (
        "Atención: la mercancía que ingresó (" + productos + ") "
        + cuando + " (" + fecha.strftime("%d/%m/%Y") + ")."
    )


def usuario_vigente():
    """
    Comprueba en la base de datos que el usuario de la sesión todavía exista
    y esté activo (así, al desactivar a un empleado, se le cierra la sesión
    al instante). También actualiza su rol.
    """
    cod_usu = session.get("cod_usu")

    if cod_usu is None:
        return False

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute(
            "SELECT nom_usu, rol, activo FROM usuarios WHERE cod_usu = %s",
            (cod_usu,)
        )
        fila = cursor.fetchone()
    finally:
        cursor.close()
        conexion.close()

    if fila is None or not fila[2]:
        session.clear()
        return False

    session["nom_usu"] = fila[0]
    session["rol"] = fila[1]
    return True


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not usuario_vigente():
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get("rol") != "Administrador":
            flash("Solo el administrador puede entrar a esa sección.", "warning")
            return redirect(url_for("menu"))
        return func(*args, **kwargs)
    return wrapper


# Descuento máximo (en %) que puede aplicar un empleado. El administrador
# puede llegar hasta 100. Cámbialo aquí si el negocio usa otro tope.
DESCUENTO_MAXIMO_EMPLEADO = 20


def descuento_maximo():
    if session.get("rol") == "Administrador":
        return Decimal("100")
    return Decimal(str(DESCUENTO_MAXIMO_EMPLEADO))


@app.after_request
def no_guardar_paginas(respuesta):
    """Evita que el navegador guarde las páginas: tras cerrar sesión, el
    botón 'atrás' no debe mostrar información."""
    if request.endpoint != "static" and respuesta.mimetype == "text/html":
        respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


# =========================
# LOGIN
# =========================

INTENTOS_MAXIMOS = 5
BLOQUEO_SEGUNDOS = 300
intentos_fallidos = {}
HASH_FALSO = generate_password_hash("clave-falsa-para-igualar-tiempos")


def segundos_de_bloqueo(llave):
    registro = intentos_fallidos.get(llave)

    if registro and registro["hasta"] > time.time():
        return int(registro["hasta"] - time.time()) + 1

    return 0


def registrar_intento_fallido(llave):
    registro = intentos_fallidos.setdefault(llave, {"n": 0, "hasta": 0})

    if registro["hasta"] and registro["hasta"] <= time.time():
        registro["n"] = 0
        registro["hasta"] = 0

    registro["n"] += 1

    if registro["n"] >= INTENTOS_MAXIMOS:
        registro["hasta"] = time.time() + BLOQUEO_SEGUNDOS
        registro["n"] = 0


@app.route("/", methods=["GET", "POST"])
def login():
    mensaje = ""

    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        clave = request.form.get("clave", "")

        llave = (usuario.lower(), request.remote_addr)
        espera = segundos_de_bloqueo(llave)

        if espera:
            minutos = (espera + 59) // 60
            mensaje = (
                "Demasiados intentos fallidos. Intenta de nuevo en "
                + str(minutos) + (" minuto." if minutos == 1 else " minutos.")
            )
            return render_template("login.html", mensaje=mensaje)

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            cursor.execute("""
                SELECT cod_usu, nom_usu, clave, rol, activo
                FROM usuarios
                WHERE LOWER(usuario) = LOWER(%s)
            """, (usuario,))

            usuario_db = cursor.fetchone()

        finally:
            cursor.close()
            conexion.close()

        # Se verifica siempre una clave (aunque el usuario no exista)
        # para que el tiempo de respuesta no delate qué usuarios existen.
        clave_correcta = check_password_hash(
            usuario_db[2] if usuario_db else HASH_FALSO,
            clave
        )

        if usuario_db and clave_correcta:

            if not usuario_db[4]:
                mensaje = "Tu usuario está desactivado. Habla con el administrador."
            else:
                intentos_fallidos.pop(llave, None)

                session.clear()
                session.permanent = True
                session["cod_usu"] = usuario_db[0]
                session["nom_usu"] = usuario_db[1]
                session["rol"] = usuario_db[3]

                return redirect(url_for("menu"))

        else:
            registrar_intento_fallido(llave)
            mensaje = "Usuario o contraseña incorrectos."

    return render_template("login.html", mensaje=mensaje)


# =========================
# MENU
# =========================

@app.route("/menu")
@login_required
def menu():
    return render_template("menu.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================
# ADMINISTRACIÓN DE USUARIOS
# =========================

ROLES = ("Administrador", "Empleado")
PATRON_USUARIO = re.compile(r"^[a-z0-9_.]{3,30}$")
LARGO_MINIMO_CLAVE = 8


def validar_clave_nueva(clave, confirmacion):
    """Devuelve un texto con el problema, o None si la clave es aceptable."""
    if len(clave) < LARGO_MINIMO_CLAVE:
        return "La contraseña debe tener al menos " + str(LARGO_MINIMO_CLAVE) + " caracteres."

    if not any(c.isalpha() for c in clave) or not any(c.isdigit() for c in clave):
        return "La contraseña debe combinar letras y números."

    if clave != confirmacion:
        return "Las dos contraseñas no coinciden."

    return None


def listar_usuarios():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT cod_usu, nom_usu, usuario, rol, activo
            FROM usuarios
            ORDER BY activo DESC, cod_usu
        """)
        return cursor.fetchall()
    finally:
        cursor.close()
        conexion.close()


def otros_administradores_activos(cursor, cod_usu):
    cursor.execute("""
        SELECT COUNT(*)
        FROM usuarios
        WHERE rol = 'Administrador' AND activo = TRUE AND cod_usu <> %s
    """, (cod_usu,))
    return cursor.fetchone()[0]


@app.route("/usuarios")
@admin_required
def usuarios():
    return render_template("usuarios/lista.html", lista=listar_usuarios(), datos={})


@app.route("/usuarios/crear", methods=["POST"])
@admin_required
def crear_usuario():
    nombre = request.form.get("nom_usu", "").strip()
    usuario = request.form.get("usuario", "").strip().lower()
    rol = request.form.get("rol", "")
    clave = request.form.get("clave", "")
    confirmar = request.form.get("confirmar", "")

    error = None

    if not nombre:
        error = "Escribe el nombre completo del empleado."
    elif not PATRON_USUARIO.match(usuario):
        error = "El usuario debe tener de 3 a 30 caracteres: letras minúsculas sin tildes, números, punto o guion bajo."
    elif rol not in ROLES:
        error = "Elige un rol válido."
    else:
        error = validar_clave_nueva(clave, confirmar)

    if not error:
        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            cursor.execute(
                "SELECT 1 FROM usuarios WHERE LOWER(usuario) = %s", (usuario,)
            )

            if cursor.fetchone():
                error = "Ya existe un usuario llamado \"" + usuario + "\"."
            else:
                cursor.execute("""
                    INSERT INTO usuarios (nom_usu, usuario, clave, rol, activo, clave_cifrada)
                    VALUES (%s, %s, %s, %s, TRUE, %s)
                """, (
                    nombre, usuario, generate_password_hash(clave), rol,
                    cifrar_clave(clave) if rol == "Empleado" else None
                ))
                conexion.commit()

        except Exception as e:
            conexion.rollback()
            print("ERROR AL CREAR USUARIO:", repr(e))
            error = "No se pudo crear el usuario."

        finally:
            cursor.close()
            conexion.close()

    if error:
        flash(error, "danger")
        # Se devuelve el formulario con lo escrito (menos las contraseñas).
        return render_template(
            "usuarios/lista.html",
            lista=listar_usuarios(),
            datos={"nom_usu": nombre, "usuario": usuario, "rol": rol}
        )

    flash("Usuario \"" + usuario + "\" creado correctamente.", "success")
    return redirect(url_for("usuarios"))


@app.route("/usuarios/<int:cod_usu>/editar", methods=["GET", "POST"])
@admin_required
def editar_usuario(cod_usu):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT cod_usu, nom_usu, usuario, rol, activo, clave_cifrada
            FROM usuarios
            WHERE cod_usu = %s
        """, (cod_usu,))
        fila = cursor.fetchone()

        if fila is None:
            flash("El usuario no existe.", "warning")
            return redirect(url_for("usuarios"))

        # Solo se muestra la contraseña de cuentas de empleado.
        clave_actual = descifrar_clave(fila[5]) if fila[3] == "Empleado" else None

        if request.method == "POST":
            nombre = request.form.get("nom_usu", "").strip()
            rol = request.form.get("rol", "")
            clave = request.form.get("clave", "")
            confirmar = request.form.get("confirmar", "")

            error = None

            if not nombre:
                error = "Escribe el nombre completo."
            elif rol not in ROLES:
                error = "Elige un rol válido."
            elif clave or confirmar:
                error = validar_clave_nueva(clave, confirmar)

            if (
                not error
                and fila[3] == "Administrador"
                and fila[4]
                and rol != "Administrador"
                and otros_administradores_activos(cursor, cod_usu) == 0
            ):
                error = "Debe quedar al menos un administrador activo."

            if error:
                flash(error, "danger")
                return render_template(
                    "usuarios/editar.html",
                    usuario=(fila[0], nombre, fila[2], rol, fila[4]),
                    clave_actual=clave_actual
                )

            if clave:
                cursor.execute("""
                    UPDATE usuarios
                    SET nom_usu = %s, rol = %s, clave = %s, clave_cifrada = %s
                    WHERE cod_usu = %s
                """, (
                    nombre, rol, generate_password_hash(clave),
                    cifrar_clave(clave) if rol == "Empleado" else None,
                    cod_usu
                ))
            elif rol == "Administrador":
                # Los administradores no guardan contraseña visible.
                cursor.execute("""
                    UPDATE usuarios
                    SET nom_usu = %s, rol = %s, clave_cifrada = NULL
                    WHERE cod_usu = %s
                """, (nombre, rol, cod_usu))
            else:
                cursor.execute("""
                    UPDATE usuarios
                    SET nom_usu = %s, rol = %s
                    WHERE cod_usu = %s
                """, (nombre, rol, cod_usu))

            conexion.commit()

            flash("Usuario actualizado correctamente.", "success")
            return redirect(url_for("usuarios"))

    except Exception as e:
        conexion.rollback()
        print("ERROR AL EDITAR USUARIO:", repr(e))
        flash("No se pudo actualizar el usuario.", "danger")
        return redirect(url_for("usuarios"))

    finally:
        cursor.close()
        conexion.close()

    return render_template("usuarios/editar.html", usuario=fila, clave_actual=clave_actual)


@app.route("/usuarios/<int:cod_usu>/estado", methods=["POST"])
@admin_required
def cambiar_estado_usuario(cod_usu):
    if cod_usu == session.get("cod_usu"):
        flash("No puedes desactivar tu propio usuario.", "warning")
        return redirect(url_for("usuarios"))

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute(
            "SELECT usuario, rol, activo FROM usuarios WHERE cod_usu = %s",
            (cod_usu,)
        )
        fila = cursor.fetchone()

        if fila is None:
            flash("El usuario no existe.", "warning")
            return redirect(url_for("usuarios"))

        nuevo_estado = not fila[2]

        if (
            not nuevo_estado
            and fila[1] == "Administrador"
            and otros_administradores_activos(cursor, cod_usu) == 0
        ):
            flash("Debe quedar al menos un administrador activo.", "danger")
            return redirect(url_for("usuarios"))

        cursor.execute(
            "UPDATE usuarios SET activo = %s WHERE cod_usu = %s",
            (nuevo_estado, cod_usu)
        )
        conexion.commit()

        flash(
            "Usuario \"" + fila[0] + "\" " + ("activado." if nuevo_estado else "desactivado."),
            "success"
        )

    except Exception as e:
        conexion.rollback()
        print("ERROR AL CAMBIAR ESTADO DE USUARIO:", repr(e))
        flash("No se pudo cambiar el estado del usuario.", "danger")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("usuarios"))


@app.route("/cuenta/clave", methods=["GET", "POST"])
@admin_required
def cambiar_mi_clave():
    # Los empleados no pueden cambiar su contraseña: si la olvidan o la
    # quieren cambiar, el administrador se la asigna desde Administración.
    if request.method == "POST":
        actual = request.form.get("actual", "")
        nueva = request.form.get("nueva", "")
        confirmar = request.form.get("confirmar", "")

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        try:
            cursor.execute(
                "SELECT clave FROM usuarios WHERE cod_usu = %s",
                (session["cod_usu"],)
            )
            fila = cursor.fetchone()

            if not fila or not check_password_hash(fila[0], actual):
                flash("La contraseña actual no es correcta.", "danger")
            elif nueva == actual:
                flash("La contraseña nueva debe ser diferente a la actual.", "danger")
            else:
                error = validar_clave_nueva(nueva, confirmar)

                if error:
                    flash(error, "danger")
                else:
                    cursor.execute(
                        "UPDATE usuarios SET clave = %s, clave_cifrada = NULL WHERE cod_usu = %s",
                        (generate_password_hash(nueva), session["cod_usu"])
                    )
                    conexion.commit()

                    flash("Tu contraseña se cambió correctamente.", "success")
                    return redirect(url_for("menu"))

        except Exception as e:
            conexion.rollback()
            print("ERROR AL CAMBIAR CONTRASEÑA:", repr(e))
            flash("No se pudo cambiar la contraseña.", "danger")

        finally:
            cursor.close()
            conexion.close()

    return render_template("usuarios/mi_clave.html")


# =========================
# PRODUCTOS - LISTAR
# =========================

@app.route("/productos")
@login_required
def productos():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_prod,
                nom_prod,
                grupo,
                clasificacion,
                precio_venta,
                stock_actual,
                unidad_medida,
                estado
            FROM productos
            ORDER BY cod_prod DESC
        """)

        productos = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "productos/lista.html",
        productos=productos
    )


# =========================
# PRODUCTOS - ACTUALIZAR
# =========================

@app.route("/productos/actualizar")
@login_required
def actualizar_productos():
    buscar = request.args.get("buscar", "")
    editar_id = request.args.get("editar")

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        if buscar:
            cursor.execute("""
                SELECT
                    cod_prod,
                    nom_prod,
                    codigo_barras,
                    grupo,
                    clasificacion,
                    precio_venta,
                    stock_actual,
                    unidad_medida,
                    estado
                FROM productos
                WHERE LOWER(nom_prod) LIKE LOWER(%s)
                   OR CAST(cod_prod AS TEXT) LIKE %s
                   OR codigo_barras LIKE %s
                ORDER BY nom_prod
            """, (
                "%" + buscar + "%",
                "%" + buscar + "%",
                "%" + buscar + "%"
            ))
        else:
            cursor.execute("""
                SELECT
                    cod_prod,
                    nom_prod,
                    codigo_barras,
                    grupo,
                    clasificacion,
                    precio_venta,
                    stock_actual,
                    unidad_medida,
                    estado
                FROM productos
                ORDER BY nom_prod
            """)

        productos = cursor.fetchall()
        producto_editar = None

        if editar_id:
            cursor.execute("""
                SELECT
                    cod_prod,
                    nom_prod,
                    codigo_barras,
                    grupo,
                    clasificacion,
                    precio_venta,
                    stock_actual,
                    unidad_medida,
                    estado
                FROM productos
                WHERE cod_prod = %s
            """, (editar_id,))

            producto_editar = cursor.fetchone()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "productos/actualizar.html",
        productos=productos,
        producto_editar=producto_editar,
        buscar=buscar
    )


# =========================
# PRODUCTOS - AGREGAR
# =========================

@app.route("/productos/agregar", methods=["POST"])
@login_required
def agregar_producto():
    conexion = None
    cursor = None

    try:
        nombre = request.form["nombre"]
        codigo_barras = request.form["codigo_barras"]
        grupo = request.form["grupo"]
        clasificacion = request.form["clasificacion"]
        precio = request.form["precio"]
        unidad = request.form["unidad"]

        # El stock inicial siempre comienza en 0.
        stock = 0

        conexion = obtener_conexion()
        cursor = conexion.cursor()

        cursor.execute("""
            INSERT INTO productos
            (
                nom_prod,
                codigo_barras,
                grupo,
                clasificacion,
                precio_venta,
                stock_actual,
                unidad_medida,
                estado
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            nombre,
            codigo_barras,
            grupo,
            clasificacion,
            precio,
            stock,
            unidad,
            "Activo"
        ))

        conexion.commit()

        flash("Producto añadido con éxito.", "success")

    except Exception as error:
        print("ERROR AL AÑADIR PRODUCTO:", error)

        if conexion:
            conexion.rollback()

        flash("El producto no se pudo añadir.", "danger")

    finally:
        if cursor:
            cursor.close()
        if conexion:
            conexion.close()

    return redirect(url_for("productos"))


# =========================
# PRODUCTOS - ELIMINAR
# =========================

@app.route("/productos/eliminar/<int:id>")
@login_required
def eliminar_producto(id):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute(
            "DELETE FROM productos WHERE cod_prod = %s",
            (id,)
        )

        conexion.commit()

    except Exception as error:
        conexion.rollback()
        print("ERROR AL ELIMINAR PRODUCTO:", error)

        flash(
            "El producto no se puede eliminar porque tiene información relacionada.",
            "danger"
        )

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("actualizar_productos"))


# =========================
# PRODUCTOS - EDITAR
# =========================

@app.route("/productos/editar/<int:id>", methods=["POST"])
@login_required
def editar_producto(id):
    nombre = request.form["nombre"]
    codigo_barras = request.form["codigo_barras"]
    grupo = request.form["grupo"]
    clasificacion = request.form["clasificacion"]
    precio = request.form["precio"]
    unidad = request.form["unidad"]
    estado = request.form["estado"]

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            UPDATE productos
            SET
                nom_prod = %s,
                codigo_barras = %s,
                grupo = %s,
                clasificacion = %s,
                precio_venta = %s,
                unidad_medida = %s,
                estado = %s
            WHERE cod_prod = %s
        """, (
            nombre,
            codigo_barras,
            grupo,
            clasificacion,
            precio,
            unidad,
            estado,
            id
        ))

        conexion.commit()

        flash("Producto actualizado correctamente.", "success")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("actualizar_productos"))


# =========================
# CLIENTES - LISTAR
# =========================

@app.route("/clientes")
@login_required
def clientes():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_cli,
                nom_cli,
                tel_cli,
                dir_cli,
                email_cli
            FROM clientes
            ORDER BY cod_cli DESC
        """)

        clientes = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "clientes/lista.html",
        clientes=clientes
    )

# =========================
# INFORME DE CLIENTES
# =========================

@app.route("/informe/clientes")
@admin_required
def informe_clientes():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_cli,
                nom_cli,
                tel_cli,
                dir_cli,
                email_cli
            FROM clientes
            ORDER BY cod_cli DESC
        """)

        clientes = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "informes/informe_cliente.html",
        clientes=clientes
)

# =========================
# CLIENTES - AGREGAR
# =========================


@app.route("/clientes/agregar", methods=["POST"])
@login_required
def agregar_cliente():
    nombre = request.form["nombre"]
    telefono = request.form["telefono"]
    direccion = request.form["direccion"]
    email = request.form["email"]

    conexion = None
    cursor = None

    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor()

        cursor.execute("""
            INSERT INTO clientes
            (
                nom_cli,
                tel_cli,
                dir_cli,
                email_cli
            )
            VALUES (%s, %s, %s, %s)
        """, (
            nombre,
            telefono,
            direccion,
            email
        ))

        conexion.commit()

        flash("¡Cliente añadido con éxito!", "success")

    except Exception as e:
        if conexion:
            conexion.rollback()

        flash("Error al añadir el cliente. Verifica los datos e inténtalo de nuevo.", "danger")

    finally:
        if cursor:
            cursor.close()
        if conexion:
            conexion.close()

    return redirect(url_for("clientes"))


# =========================
# CLIENTES - EDITAR
# =========================

@app.route("/clientes/editar/<int:id>", methods=["GET", "POST"])
@admin_required
def editar_cliente(id):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        if request.method == "POST":
            nombre = request.form["nombre"]
            telefono = request.form["telefono"]
            direccion = request.form["direccion"]
            email = request.form["email"]

            cursor.execute("""
                UPDATE clientes
                SET
                    nom_cli = %s,
                    tel_cli = %s,
                    dir_cli = %s,
                    email_cli = %s
                WHERE cod_cli = %s
            """, (
                nombre,
                telefono,
                direccion,
                email,
                id
            ))

            conexion.commit()
            return redirect(url_for("clientes"))

        cursor.execute("""
            SELECT
                cod_cli,
                nom_cli,
                tel_cli,
                dir_cli,
                email_cli
            FROM clientes
            WHERE cod_cli = %s
        """, (id,))

        cliente = cursor.fetchone()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "clientes/editar.html",
        cliente=cliente
    )


# =========================
# CLIENTES - ELIMINAR
# =========================

@app.route("/clientes/eliminar/<int:id>")
@admin_required
def eliminar_cliente(id):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT COUNT(*)
            FROM ventas
            WHERE cod_cli = %s
        """, (id,))

        cantidad_ventas = cursor.fetchone()[0]

        if cantidad_ventas > 0:
            # Se conserva el cliente para no perder el historial de ventas.
            flash(
                "No se puede eliminar este cliente porque tiene "
                + str(cantidad_ventas)
                + " venta(s) registrada(s).",
                "warning"
            )
        else:
            cursor.execute(
                "DELETE FROM clientes WHERE cod_cli = %s",
                (id,)
            )

            conexion.commit()

            flash("Cliente eliminado correctamente.", "success")

    except Exception as error:
        conexion.rollback()

        print("ERROR AL ELIMINAR CLIENTE:", error)

        flash("No se pudo eliminar el cliente.", "danger")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("clientes"))


# =========================
# PROVEEDORES - LISTAR
# =========================

@app.route("/proveedores")
@admin_required
def proveedores():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_prov,
                nom_prov,
                nit,
                tel_prov,
                dir_prov,
                email_prov,
                estado
            FROM proveedores
            ORDER BY cod_prov DESC
        """)

        proveedores = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "proveedores/lista.html",
        proveedores=proveedores
    )


# =========================
# PROVEEDORES - AGREGAR
# =========================


@app.route("/proveedores/agregar", methods=["POST"])
@admin_required
def agregar_proveedor():
    nombre = request.form["nombre"]
    nit = request.form["nit"]
    telefono = request.form["telefono"]
    direccion = request.form["direccion"]
    email = request.form["email"]

    conexion = None
    cursor = None

    try:
        conexion = obtener_conexion()
        cursor = conexion.cursor()

        cursor.execute("""
            INSERT INTO proveedores
            (
                nom_prov,
                nit,
                tel_prov,
                dir_prov,
                email_prov
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            nombre,
            nit,
            telefono,
            direccion,
            email
        ))

        conexion.commit()

        flash("¡Proveedor añadido con éxito!", "success")

    except Exception:
        if conexion:
            conexion.rollback()

        flash(
            "Error al añadir el proveedor. Verifica los datos e inténtalo de nuevo.",
            "danger"
        )

    finally:
        if cursor:
            cursor.close()
        if conexion:
            conexion.close()

    return redirect(url_for("proveedores"))

# =========================
# PROVEEDORES - EDITAR
# =========================

@app.route("/proveedores/editar/<int:id>", methods=["GET", "POST"])
@admin_required
def editar_proveedor(id):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        if request.method == "POST":
            nombre = request.form["nombre"]
            nit = request.form["nit"]
            telefono = request.form["telefono"]
            direccion = request.form["direccion"]
            email = request.form["email"]
            estado = request.form["estado"]

            cursor.execute("""
                UPDATE proveedores
                SET
                    nom_prov = %s,
                    nit = %s,
                    tel_prov = %s,
                    dir_prov = %s,
                    email_prov = %s,
                    estado = %s
                WHERE cod_prov = %s
            """, (
                nombre,
                nit,
                telefono,
                direccion,
                email,
                estado,
                id
            ))

            conexion.commit()
            return redirect(url_for("proveedores"))

        cursor.execute("""
            SELECT
                cod_prov,
                nom_prov,
                nit,
                tel_prov,
                dir_prov,
                email_prov,
                estado
            FROM proveedores
            WHERE cod_prov = %s
        """, (id,))

        proveedor = cursor.fetchone()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "proveedores/editar.html",
        proveedor=proveedor
    )


# =========================
# PROVEEDORES - ELIMINAR
# =========================

@app.route("/proveedores/eliminar/<int:id>")
@admin_required
def eliminar_proveedor(id):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT estado
            FROM proveedores
            WHERE cod_prov = %s
        """, (id,))

        proveedor = cursor.fetchone()

        if proveedor is None:
            flash("El proveedor ya no existe.", "warning")
            return redirect(url_for("proveedores"))

        estado = proveedor[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM lotes_producto
            WHERE cod_prov = %s
        """, (id,))

        cantidad_lotes = cursor.fetchone()[0]

        if cantidad_lotes == 0:
            # Sin mercancía registrada: se puede borrar de verdad.
            cursor.execute("""
                DELETE FROM proveedores
                WHERE cod_prov = %s
            """, (id,))

            conexion.commit()

            flash("Proveedor eliminado correctamente.", "success")

        elif estado == "Activo":
            # Con mercancía registrada solo se puede desactivar.
            cursor.execute("""
                UPDATE proveedores
                SET estado = 'Inactivo'
                WHERE cod_prov = %s
            """, (id,))

            conexion.commit()

            flash(
                "El proveedor tiene entradas de mercancía registradas, "
                "así que no se puede borrar. Se marcó como Inactivo.",
                "warning"
            )

        else:
            # Ya estaba inactivo: se explica por qué no desaparece.
            flash(
                "Este proveedor ya está Inactivo y no se puede borrar "
                "porque tiene entradas de mercancía registradas.",
                "info"
            )

    except Exception as error:
        conexion.rollback()

        print("ERROR AL ELIMINAR PROVEEDOR:", error)

        flash("No se pudo eliminar el proveedor.", "danger")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("proveedores"))


# =========================
# INFORME DE PROVEEDORES
# =========================

@app.route("/informes/proveedores")
@admin_required
def informe_proveedores():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_prov,
                nom_prov,
                nit,
                tel_prov,
                dir_prov,
                email_prov,
                estado
            FROM proveedores
            ORDER BY cod_prov DESC
        """)

        proveedores = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "informes/informe_proovedores.html",
        proveedores=proveedores
    )



# =========================
# PUNTO DE VENTA - PANTALLA
# =========================

@app.route("/ventas")
@login_required
def ventas():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT cod_cli, nom_cli
            FROM clientes
            ORDER BY nom_cli
        """)

        clientes_db = cursor.fetchall()

        cursor.execute("""
            SELECT
                cod_prod,
                nom_prod,
                precio_venta,
                stock_actual,
                unidad_medida,
                codigo_barras
            FROM productos
            WHERE estado = 'Activo'
              AND stock_actual > 0
            ORDER BY nom_prod
        """)

        productos_db = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    # Se convierten los resultados a diccionarios
    # para que el JavaScript del punto de venta los pueda usar.

    clientes = [
        {
            "cod_cli": cliente[0],
            "nombre": cliente[1]
        }
        for cliente in clientes_db
    ]

    productos = [
        {
            "cod_prod": producto[0],
            "nombre": producto[1],
            "precio": float(producto[2]),
            "stock": producto[3],
            "unidad": producto[4],
            "barras": producto[5] or ""
        }
        for producto in productos_db
    ]

    return render_template(
        "ventas/punto_venta.html",
        clientes=clientes,
        productos=productos,
        max_descuento=int(descuento_maximo())
    )


# =========================
# PUNTO DE VENTA - CONSULTAR PRODUCTOS
# =========================

@app.route("/pos/productos")
@login_required
def pos_productos():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_prod,
                nom_prod,
                precio_venta,
                stock_actual,
                unidad_medida,
                codigo_barras
            FROM productos
            WHERE estado = 'Activo'
              AND stock_actual > 0
            ORDER BY nom_prod
        """)

        resultados = cursor.fetchall()

        productos = [
            {
                "cod_prod": producto[0],
                "nombre": producto[1],
                "precio": float(producto[2]),
                "stock": producto[3],
                "unidad": producto[4],
                "barras": producto[5] or ""
            }
            for producto in resultados
        ]

        return jsonify(productos)

    finally:
        cursor.close()
        conexion.close()


# =========================
# PUNTO DE VENTA - GUARDAR VENTA
# =========================

@app.route("/pos/guardar", methods=["POST"])
@login_required
def pos_guardar():
    datos = request.get_json(silent=True)

    if not datos:
        return jsonify({
            "ok": False,
            "error": "No se recibieron los datos de la venta."
        }), 400

    cod_cli = datos.get("cod_cli")
    items = datos.get("items")

    if not cod_cli:
        return jsonify({
            "ok": False,
            "error": "Debes seleccionar un cliente."
        }), 400

    if not isinstance(items, list) or not items:
        return jsonify({
            "ok": False,
            "error": "La venta no tiene productos."
        }), 400

    try:
        cod_cli = int(cod_cli)

        # Se agrupan los productos repetidos para
        # comprobar y descontar bien las cantidades.
        cantidades = {}
        descuentos = {}

        for item in items:
            cod_prod = int(item["cod_prod"])
            cantidad = int(item["cantidad"])

            if cantidad <= 0:
                raise ValueError(
                    "Las cantidades deben ser mayores que cero."
                )

            # Descuento en % para este producto (0 si no se aplica).
            descuento = Decimal(str(item.get("descuento") or 0))

            if descuento < 0 or descuento > descuento_maximo():
                return jsonify({
                    "ok": False,
                    "error": (
                        "El descuento debe estar entre 0% y "
                        + str(int(descuento_maximo())) + "%."
                    )
                }), 400

            descuentos[cod_prod] = descuento

            cantidades[cod_prod] = (
                cantidades.get(cod_prod, 0) + cantidad
            )

    except (ValueError, TypeError, KeyError, InvalidOperation):
        return jsonify({
            "ok": False,
            "error": "Los productos o las cantidades no son válidos."
        }), 400

    cod_usu = session.get("cod_usu")

    if not cod_usu:
        return jsonify({
            "ok": False,
            "error": "Tu sesión terminó. Inicia sesión nuevamente."
        }), 401

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        # Comprobar que el cliente exista.
        cursor.execute("""
            SELECT cod_cli
            FROM clientes
            WHERE cod_cli = %s
        """, (cod_cli,))

        if cursor.fetchone() is None:
            raise Exception("El cliente seleccionado no existe.")

        total = Decimal("0.00")
        productos_venta = []

        # Revisar el precio y el stock actual de cada producto.
        # FOR UPDATE evita que otra venta modifique el mismo
        # producto mientras se procesa esta transacción.
        for cod_prod, cantidad in sorted(cantidades.items()):
            cursor.execute("""
                SELECT
                    cod_prod,
                    nom_prod,
                    precio_venta,
                    stock_actual
                FROM productos
                WHERE cod_prod = %s
                  AND estado = 'Activo'
                FOR UPDATE
            """, (cod_prod,))

            producto = cursor.fetchone()

            if producto is None:
                raise Exception(
                    "Uno de los productos no existe o está inactivo."
                )

            precio = Decimal(str(producto[2]))
            stock = producto[3]

            if cantidad > stock:
                raise Exception(
                    "No hay suficiente stock de "
                    + producto[1]
                    + ". Disponible: "
                    + str(stock)
                )

            bruto = precio * cantidad

            descuento_valor = (
                bruto * descuentos.get(cod_prod, Decimal("0")) / Decimal("100")
            ).quantize(CENTAVOS, rounding=ROUND_HALF_UP)

            subtotal = bruto - descuento_valor
            total += subtotal

            productos_venta.append({
                "cod_prod": cod_prod,
                "cantidad": cantidad,
                "precio": precio,
                "descuento": descuento_valor,
                "subtotal": subtotal
            })

        # Registrar la venta.
        cursor.execute("""
            INSERT INTO ventas
            (
                cod_cli,
                cod_usu,
                total,
                estado
            )
            VALUES (%s, %s, %s, 'Completada')
            RETURNING cod_ven
        """, (
            cod_cli,
            cod_usu,
            total
        ))

        cod_ven = cursor.fetchone()[0]

        # Guardar el detalle y actualizar las existencias.
        for item in productos_venta:
            # Descontar de los lotes: primero el que vence antes (FIFO).
            cursor.execute("""
                SELECT cod_lote, cantidad_disponible
                FROM lotes_producto
                WHERE cod_prod = %s
                  AND estado = 'Activo'
                  AND cantidad_disponible > 0
                ORDER BY fecha_vencimiento ASC NULLS LAST, cod_lote ASC
                FOR UPDATE
            """, (item["cod_prod"],))

            pendiente = item["cantidad"]
            tramos = []

            for cod_lote, disponible in cursor.fetchall():
                if pendiente == 0:
                    break

                tomar = min(disponible, pendiente)

                cursor.execute("""
                    UPDATE lotes_producto
                    SET cantidad_disponible = cantidad_disponible - %s
                    WHERE cod_lote = %s
                """, (tomar, cod_lote))

                tramos.append((cod_lote, tomar))
                pendiente -= tomar

            # Existencias antiguas que no tienen lote registrado.
            if pendiente > 0:
                tramos.append((None, pendiente))

            # Un renglón de detalle por cada lote usado.
            # El descuento se reparte entre los renglones según la cantidad;
            # el último se queda con el sobrante de centavos.
            descuento_pendiente = item["descuento"]

            for posicion, (cod_lote, cantidad_tramo) in enumerate(tramos):
                if posicion == len(tramos) - 1:
                    descuento_tramo = descuento_pendiente
                else:
                    descuento_tramo = (
                        item["descuento"] * cantidad_tramo / item["cantidad"]
                    ).quantize(CENTAVOS, rounding=ROUND_HALF_UP)
                    descuento_pendiente -= descuento_tramo

                cursor.execute("""
                    INSERT INTO detalle_venta
                    (
                        cod_ven,
                        cod_prod,
                        cod_lote,
                        descuento,
                        cantidad,
                        subtotal
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    cod_ven,
                    item["cod_prod"],
                    cod_lote,
                    descuento_tramo,
                    cantidad_tramo,
                    item["precio"] * cantidad_tramo - descuento_tramo
                ))

            mover_stock(cursor, item["cod_prod"], -item["cantidad"])

            # Sincronizar stock_en con el stock de productos.
            cursor.execute("""
                INSERT INTO stock_en
                (
                    cod_prod,
                    cantidad_actual,
                    stock_minimo
                )
                SELECT cod_prod, stock_actual, 5
                FROM productos
                WHERE cod_prod = %s
                ON CONFLICT (cod_prod)
                DO UPDATE SET
                    cantidad_actual = EXCLUDED.cantidad_actual
            """, (item["cod_prod"],))

        conexion.commit()

        return jsonify({
            "ok": True,
            "cod_ven": cod_ven,
            "total": float(total)
        })

    except Exception as error:
        conexion.rollback()

        print("ERROR AL GUARDAR VENTA DEL PUNTO DE VENTA:", error)

        return jsonify({
            "ok": False,
            "error": str(error)
        }), 400

    finally:
        cursor.close()
        conexion.close()


# =========================
# INVENTARIO - PANTALLA
# =========================

@app.route("/inventario")
@login_required
def inventario():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_prod,
                nom_prod || CASE WHEN estado = 'Activo' THEN '' ELSE ' (inactivo)' END
            FROM productos
            ORDER BY nom_prod
        """)
        productos = cursor.fetchall()

        cursor.execute("""
            SELECT cod_prov, nom_prov
            FROM proveedores
            WHERE estado = 'Activo'
            ORDER BY nom_prov
        """)
        proveedores = cursor.fetchall()

        cursor.execute("""
            SELECT cod_bod, nom_bod
            FROM bodegas
            WHERE estado = 'Activo'
            ORDER BY nom_bod
        """)
        bodegas = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "inventario/entrada_mercancia.html",
        productos=productos,
        proveedores=proveedores,
        bodegas=bodegas
    )


# =========================
# INVENTARIO - ENTRADA DE MERCANCÍA
# =========================

@app.route("/inventario/entrada_mercancia")
@login_required
def entrada_mercancia():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_prod,
                nom_prod || CASE WHEN estado = 'Activo' THEN '' ELSE ' (inactivo)' END
            FROM productos
            ORDER BY nom_prod
        """)
        productos = cursor.fetchall()

        cursor.execute("""
            SELECT cod_prov, nom_prov
            FROM proveedores
            WHERE estado = 'Activo'
            ORDER BY nom_prov
        """)
        proveedores = cursor.fetchall()

        cursor.execute("""
            SELECT cod_bod, nom_bod
            FROM bodegas
            WHERE estado = 'Activo'
            ORDER BY nom_bod
        """)
        bodegas = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "inventario/entrada_mercancia.html",
        productos=productos,
        proveedores=proveedores,
        bodegas=bodegas
    )


# =========================
# INVENTARIO - GUARDAR ENTRADA
# =========================

@app.route("/inventario/entrada_mercancia", methods=["POST"])
@login_required
def guardar_entrada_mercancia():
    productos = request.form.getlist("productos[]")
    cantidades = request.form.getlist("cantidades[]")
    cod_prov = request.form.get("cod_prov")
    lote = request.form.get("lote")
    fecha_fabricacion = request.form.get("fecha_fabricacion")
    fecha_vencimiento = request.form.get("fecha_vencimiento")
    cod_bod = request.form.get("cod_bod")

    if not productos:
        flash("Debes añadir al menos un producto.", "danger")
        return redirect(url_for("entrada_mercancia"))

    if not cod_prov:
        flash("Debes seleccionar un proveedor.", "danger")
        return redirect(url_for("entrada_mercancia"))

    if not cod_bod:
        flash("Debes seleccionar una bodega.", "danger")
        return redirect(url_for("entrada_mercancia"))

    if len(productos) != len(cantidades):
        flash("Los datos de los productos no son válidos.", "danger")
        return redirect(url_for("entrada_mercancia"))

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT cod_prov
            FROM proveedores
            WHERE cod_prov = %s AND estado = 'Activo'
        """, (cod_prov,))

        if cursor.fetchone() is None:
            raise Exception("El proveedor seleccionado no existe o está inactivo.")

        cursor.execute("""
            SELECT cod_bod
            FROM bodegas
            WHERE cod_bod = %s AND estado = 'Activo'
        """, (cod_bod,))

        if cursor.fetchone() is None:
            raise Exception("La bodega seleccionada no existe o está inactiva.")

        nombres = []

        for i in range(len(productos)):
            try:
                cod_prod = int(productos[i])
                cantidad = int(cantidades[i])
            except (ValueError, TypeError):
                raise Exception("El producto o la cantidad no son válidos.")

            if cantidad <= 0:
                raise Exception("La cantidad debe ser mayor que 0.")

            cursor.execute("""
                SELECT cod_prod, nom_prod
                FROM productos
                WHERE cod_prod = %s
                FOR UPDATE
            """, (cod_prod,))

            producto = cursor.fetchone()

            if producto is None:
                raise Exception("El producto seleccionado no existe.")

            nombres.append(producto[1])

            cursor.execute("""
                INSERT INTO lotes_producto
                (
                    cod_prod,
                    cod_prov,
                    lote,
                    fecha_fabricacion,
                    fecha_vencimiento,
                    cantidad_inicial,
                    cantidad_disponible,
                    ubicacion_bodega,
                    estado
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Activo')
            """, (
                cod_prod,
                cod_prov,
                lote,
                fecha_fabricacion or None,
                fecha_vencimiento or None,
                cantidad,
                cantidad,
                cod_bod
            ))

            mover_stock(cursor, cod_prod, cantidad)

            sincronizar_stock_en(cursor, cod_prod)

        conexion.commit()
        flash("Entrada de mercancía registrada correctamente.", "success")

        aviso = aviso_entrada_por_vencer(fecha_vencimiento, nombres)

        if aviso:
            flash(aviso, "warning")

    except Exception as error:
        conexion.rollback()
        print("ERROR AL REGISTRAR ENTRADA:", error)

        flash(
            "La entrada de mercancía no se pudo registrar: " + str(error),
            "danger"
        )

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("entrada_mercancia"))


# =========================
# INVENTARIO - AJUSTE
# =========================

@app.route("/inventario/ajuste")
@login_required
def ajuste_inventario():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT cod_prod, nom_prod, codigo_barras
            FROM productos
            ORDER BY nom_prod
        """)
        productos = cursor.fetchall()

        cursor.execute("""
            SELECT cod_bod, nom_bod
            FROM bodegas
            WHERE estado = 'Activo'
            ORDER BY nom_bod
        """)
        bodegas = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "inventario/ajuste_inventario.html",
        productos=productos,
        bodegas=bodegas
    )


# =========================
# INVENTARIO - GUARDAR AJUSTE
# =========================

@app.route("/inventario/ajuste", methods=["POST"])
@login_required
def guardar_ajuste_inventario():
    productos = request.form.getlist("productos[]")
    cantidades = request.form.getlist("cantidades[]")
    bodegas = request.form.getlist("bodegas[]")

    if not productos:
        flash("Debes añadir al menos un producto.", "danger")
        return redirect(url_for("ajuste_inventario"))

    if len(productos) != len(cantidades) or len(productos) != len(bodegas):
        flash("Los datos del ajuste no son válidos.", "danger")
        return redirect(url_for("ajuste_inventario"))

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        for i in range(len(productos)):
            producto = productos[i].strip()

            try:
                cantidad = int(cantidades[i])
                cod_bod = int(bodegas[i])
            except ValueError:
                raise Exception("La cantidad o la bodega seleccionada no son válidas.")

            cursor.execute("""
                SELECT cod_prod, nom_prod, stock_actual
                FROM productos
                WHERE (
                    nom_prod = %s
                    OR codigo_barras = %s
                    OR CAST(cod_prod AS TEXT) = %s
                )
                FOR UPDATE
            """, (producto, producto, producto))

            resultado = cursor.fetchone()

            if resultado is None:
                raise Exception("El producto '" + producto + "' no existe.")

            cod_prod = resultado[0]
            nom_prod = resultado[1]
            stock_actual = resultado[2]

            cursor.execute("""
                SELECT cod_bod
                FROM bodegas
                WHERE cod_bod = %s AND estado = 'Activo'
            """, (cod_bod,))

            if cursor.fetchone() is None:
                raise Exception("La bodega seleccionada no existe o está inactiva.")

            if cantidad == 0:
                raise Exception("La cantidad del ajuste no puede ser 0.")

            nuevo_stock = stock_actual + cantidad

            if nuevo_stock < 0:
                raise Exception(
                    "El producto '" + nom_prod +
                    "' no puede quedar con stock negativo."
                )

            if cantidad < 0:
                # Existencias que nunca tuvieron lote (registros antiguos).
                cursor.execute("""
                    SELECT COALESCE(SUM(cantidad_disponible), 0)
                    FROM lotes_producto
                    WHERE cod_prod = %s AND estado = 'Activo'
                """, (cod_prod,))

                sin_lote = stock_actual - cursor.fetchone()[0]

                tramos, pendiente = descontar_lotes(
                    cursor, cod_prod, -cantidad, cod_bod
                )

                if pendiente > max(sin_lote, 0):
                    raise Exception(
                        "En la bodega seleccionada no hay suficientes "
                        "unidades de '" + nom_prod + "'. "
                        "Disponibles en esa bodega: "
                        + str(-cantidad - pendiente) + "."
                    )
            else:
                cursor.execute("""
                    SELECT cod_lote
                    FROM lotes_producto
                    WHERE cod_prod = %s
                      AND ubicacion_bodega = %s
                      AND estado = 'Activo'
                    ORDER BY cod_lote DESC
                    LIMIT 1
                    FOR UPDATE
                """, (cod_prod, cod_bod))

                lote = cursor.fetchone()

                if lote is None:
                    raise Exception(
                        "'" + nom_prod + "' no tiene lotes en esa bodega. "
                        "Registra primero una entrada de mercancía."
                    )

                cursor.execute("""
                    UPDATE lotes_producto
                    SET cantidad_disponible = cantidad_disponible + %s
                    WHERE cod_lote = %s
                """, (cantidad, lote[0]))

            cursor.execute("""
                INSERT INTO ajustes_inventario
                (cod_prod, cod_bod, cantidad)
                VALUES (%s, %s, %s)
            """, (cod_prod, cod_bod, cantidad))

            mover_stock(cursor, cod_prod, cantidad)

            sincronizar_stock_en(cursor, cod_prod)

        conexion.commit()
        flash("Ajuste de inventario registrado correctamente.", "success")

    except Exception as error:
        conexion.rollback()
        print("ERROR AL REALIZAR AJUSTE:", error)

        flash(
            "El ajuste de inventario no se pudo realizar: " + str(error),
            "danger"
        )

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("ajuste_inventario"))


# =========================
# BODEGAS - LISTAR
# =========================

@app.route("/bodegas")
@admin_required
def bodegas():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                cod_bod,
                nom_bod,
                dir_bod,
                descripcion,
                estado
            FROM bodegas
            ORDER BY cod_bod
        """)
        bodegas = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template("bodegas/lista.html", bodegas=bodegas)


# =========================
# BODEGAS - AGREGAR
# =========================

@app.route("/bodegas/agregar", methods=["POST"])
@admin_required
def agregar_bodega():
    nom_bod = request.form["nom_bod"]
    dir_bod = request.form["dir_bod"]
    descripcion = request.form["descripcion"]
    estado = request.form["estado"]

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            INSERT INTO bodegas
            (
                nom_bod,
                dir_bod,
                descripcion,
                estado
            )
            VALUES (%s, %s, %s, %s)
        """, (nom_bod, dir_bod, descripcion, estado))

        conexion.commit()

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("bodegas"))


# =========================
# BODEGAS - EDITAR
# =========================

@app.route("/bodegas/editar/<int:id>", methods=["GET", "POST"])
@admin_required
def editar_bodega(id):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        if request.method == "POST":
            nom_bod = request.form["nom_bod"]
            dir_bod = request.form["dir_bod"]
            descripcion = request.form["descripcion"]
            estado = request.form["estado"]

            cursor.execute("""
                UPDATE bodegas
                SET
                    nom_bod = %s,
                    dir_bod = %s,
                    descripcion = %s,
                    estado = %s
                WHERE cod_bod = %s
            """, (nom_bod, dir_bod, descripcion, estado, id))

            conexion.commit()
            return redirect(url_for("bodegas"))

        cursor.execute("""
            SELECT
                cod_bod,
                nom_bod,
                dir_bod,
                descripcion,
                estado
            FROM bodegas
            WHERE cod_bod = %s
        """, (id,))

        bodega = cursor.fetchone()

    finally:
        cursor.close()
        conexion.close()

    return render_template("bodegas/editar.html", bodega=bodega)


# =========================
# BODEGAS - ELIMINAR
# =========================

@app.route("/bodegas/eliminar/<int:id>")
@admin_required
def eliminar_bodega(id):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT estado
            FROM bodegas
            WHERE cod_bod = %s
        """, (id,))

        bodega = cursor.fetchone()

        if bodega is None:
            flash("La bodega ya no existe.", "warning")
            return redirect(url_for("bodegas"))

        estado = bodega[0]

        # Movimientos que dependen de esta bodega.
        cursor.execute("""
            SELECT
                (SELECT COUNT(*) FROM lotes_producto
                  WHERE ubicacion_bodega = %s),
                (SELECT COUNT(*) FROM ajustes_inventario
                  WHERE cod_bod = %s),
                (SELECT COALESCE(SUM(cantidad_disponible), 0)
                   FROM lotes_producto
                  WHERE ubicacion_bodega = %s AND estado = 'Activo')
        """, (id, id, id))

        lotes, ajustes, existencias = cursor.fetchone()

        if lotes == 0 and ajustes == 0:
            # Sin movimientos: se puede borrar de verdad.
            cursor.execute("""
                DELETE FROM bodegas
                WHERE cod_bod = %s
            """, (id,))

            conexion.commit()

            flash("Bodega eliminada correctamente.", "success")

        elif estado != "Activo":
            flash(
                "Esta bodega ya está Inactiva y no se puede borrar "
                "porque tiene movimientos de inventario registrados.",
                "info"
            )

        elif existencias > 0:
            # Si se desactivara, esas existencias dejarían de verse en los informes.
            flash(
                "La bodega todavía tiene " + str(existencias) +
                " unidad(es) en existencia. Muévelas o ajústalas "
                "antes de desactivarla.",
                "warning"
            )

        else:
            cursor.execute("""
                UPDATE bodegas
                SET estado = 'Inactivo'
                WHERE cod_bod = %s
            """, (id,))

            conexion.commit()

            flash(
                "La bodega tiene movimientos de inventario registrados, "
                "así que no se puede borrar. Se marcó como Inactiva.",
                "warning"
            )

    except Exception as error:
        conexion.rollback()

        print("ERROR AL ELIMINAR BODEGA:", error)

        flash("No se pudo eliminar la bodega.", "danger")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("bodegas"))


# =========================
# FACTURA DE VENTA
# =========================

def obtener_datos_factura(cursor, cod_ven):
    """Devuelve (venta, renglones) de una factura, o (None, []) si no existe."""
    cursor.execute("""
        SELECT
            v.cod_ven,
            v.fecha,
            v.total,
            v.estado,
            c.nom_cli,
            c.tel_cli,
            c.dir_cli,
            c.email_cli,
            u.nom_usu
        FROM ventas v
        INNER JOIN clientes c
            ON v.cod_cli = c.cod_cli
        INNER JOIN usuarios u
            ON v.cod_usu = u.cod_usu
        WHERE v.cod_ven = %s
    """, (cod_ven,))

    venta = cursor.fetchone()

    if venta is None:
        return None, []

    # Una venta puede tener varios renglones del mismo producto
    # (uno por cada lote usado); aquí se muestran sumados.
    cursor.execute("""
        SELECT
            p.nom_prod,
            p.unidad_medida,
            SUM(d.cantidad),
            SUM(d.subtotal),
            SUM(d.descuento)
        FROM detalle_venta d
        INNER JOIN productos p
            ON d.cod_prod = p.cod_prod
        WHERE d.cod_ven = %s
        GROUP BY d.cod_prod, p.nom_prod, p.unidad_medida
        ORDER BY MIN(d.cod_detalle)
    """, (cod_ven,))

    renglones = [
        {
            "producto": r[0],
            "unidad": r[1],
            "cantidad": r[2],
            "precio": ((r[3] + r[4]) / r[2]) if r[2] else 0,
            "descuento": r[4],
            "subtotal": r[3]
        }
        for r in cursor.fetchall()
    ]

    return venta, renglones


@app.route("/factura/<int:cod_ven>")
@login_required
def factura(cod_ven):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        venta, renglones = obtener_datos_factura(cursor, cod_ven)
    finally:
        cursor.close()
        conexion.close()

    if venta is None:
        flash("La venta solicitada no existe.", "warning")
        return redirect(
            url_for("informes" if es_administrador() else "ventas")
        )

    return render_template(
        "ventas/factura.html",
        venta=venta,
        renglones=renglones,
        imprimir=request.args.get("imprimir") == "1"
    )


# =========================
# ENVIAR FACTURA POR CORREO
# =========================

PATRON_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logo_para_correo():
    """Logo reducido para incrustarlo en el correo (None si no se puede)."""
    try:
        from PIL import Image

        ruta = os.path.join(app.static_folder, "img", "logo.png")
        imagen = Image.open(ruta).convert("RGBA")
        imagen.thumbnail((220, 220))
        salida = io.BytesIO()
        imagen.save(salida, format="PNG", optimize=True)
        return salida.getvalue()
    except Exception as error:
        print("NO SE PUDO PREPARAR EL LOGO DEL CORREO:", error)
        return None


def enviar_correo_factura(destino, venta, renglones):
    """Arma y envía la factura por correo. Lanza excepción si falla."""
    numero = "%06d" % venta[0]
    logo = logo_para_correo()

    html = render_template(
        "ventas/factura_email.html",
        venta=venta,
        renglones=renglones,
        numero=numero,
        con_logo=logo is not None,
        nombre_negocio=EMAIL_CONFIG["nombre"]
    )

    texto = "Factura N° {}\nCliente: {}\nFecha: {}\n\n".format(
        numero, venta[4], venta[1].strftime("%d/%m/%Y")
    )
    for r in renglones:
        texto += "- {}: {} {} x ${:,.0f} = ${:,.0f}\n".format(
            r["producto"], r["cantidad"], r["unidad"], r["precio"], r["subtotal"]
        )
    texto += "\nTotal: ${:,.0f}\n\n¡Gracias por su compra!".format(venta[2])

    mensaje = EmailMessage()
    mensaje["Subject"] = "Factura {} - {}".format(numero, EMAIL_CONFIG["nombre"])
    mensaje["From"] = "{} <{}>".format(EMAIL_CONFIG["nombre"], EMAIL_CONFIG["user"])
    mensaje["To"] = destino
    mensaje.set_content(texto)
    mensaje.add_alternative(html, subtype="html")

    if logo:
        mensaje.get_payload()[1].add_related(
            logo, maintype="image", subtype="png", cid="<logo>"
        )

    host = EMAIL_CONFIG["host"]
    puerto = EMAIL_CONFIG["port"]

    # Puerto 465 = conexión cifrada desde el inicio (SSL).
    # Puerto 587 (u otro) = conexión normal que luego se cifra (STARTTLS).
    if puerto == 465:
        servidor = smtplib.SMTP_SSL(host, puerto, timeout=20)
    else:
        servidor = smtplib.SMTP(host, puerto, timeout=20)

    with servidor:
        if puerto != 465:
            servidor.ehlo()
            servidor.starttls()
            servidor.ehlo()
        servidor.login(EMAIL_CONFIG["user"], EMAIL_CONFIG["password"])
        servidor.send_message(mensaje)


@app.route("/factura/<int:cod_ven>/enviar", methods=["POST"])
@login_required
def enviar_factura(cod_ven):
    origen = request.form.get("origen", "factura")
    destino = request.form.get("email", "").strip()

    def volver():
        if origen == "informes":
            return redirect(url_for("informes"))
        return redirect(url_for("factura", cod_ven=cod_ven))

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        venta, renglones = obtener_datos_factura(cursor, cod_ven)
    finally:
        cursor.close()
        conexion.close()

    if venta is None:
        flash("La venta solicitada no existe.", "warning")
        return redirect(url_for("informes"))

    # Si no escribieron un correo, se usa el del cliente.
    if not destino:
        destino = (venta[7] or "").strip()

    if not destino:
        flash("El cliente no tiene correo registrado. Escríbelo para poder enviar la factura.", "warning")
        return redirect(url_for("factura", cod_ven=cod_ven))

    if not PATRON_EMAIL.match(destino):
        flash("El correo \"" + destino + "\" no es válido.", "danger")
        return redirect(url_for("factura", cod_ven=cod_ven))

    try:
        enviar_correo_factura(destino, venta, renglones)
    except smtplib.SMTPAuthenticationError:
        flash("No se pudo iniciar sesión en el correo de la tienda. Revisa CORREO_USUARIO y CORREO_CLAVE en config.py.", "danger")
        return volver()
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, ConnectionError, TimeoutError, OSError) as error:
        print("ERROR DE CONEXIÓN AL ENVIAR FACTURA:", repr(error))
        flash(
            "No se pudo conectar con el servidor de correo (" + EMAIL_CONFIG["host"] + ":"
            + str(EMAIL_CONFIG["port"]) + "). Revisa el servidor y el puerto en config.py, "
            "tu conexión a internet, y que el antivirus o firewall no bloquee el puerto.",
            "danger"
        )
        return volver()
    except Exception as error:
        print("ERROR AL ENVIAR FACTURA:", repr(error))
        flash("No se pudo enviar la factura: " + str(error), "danger")
        return volver()

    flash("Factura " + ("%06d" % cod_ven) + " enviada a " + destino + ".", "success")
    return volver()


# =========================
# INFORMES
# =========================

def rango_fechas_informe(cursor):
    """Lee ?desde=...&hasta=... (por defecto, desde la primera venta hasta hoy)."""
    def leer_fecha(nombre, defecto):
        try:
            return date.fromisoformat(request.args.get(nombre, ""))
        except ValueError:
            return defecto

    hoy = date.today()

    cursor.execute("SELECT MIN(fecha) FROM ventas")
    primera_venta = cursor.fetchone()[0] or hoy

    desde = leer_fecha("desde", primera_venta)
    hasta = leer_fecha("hasta", max(hoy, primera_venta))

    if desde > hasta:
        desde, hasta = hasta, desde

    return desde, hasta


def consultar_ventas_por_dia(cursor, desde, hasta):
    """Ventas agrupadas por día. Solo suman las 'Completada'."""
    cursor.execute("""
        SELECT
            v.fecha,
            COUNT(*) FILTER (WHERE v.estado = 'Completada') AS ventas,
            COALESCE(
                SUM(v.total - COALESCE(d.devuelto, 0))
                FILTER (WHERE v.estado = 'Completada'),
                0
            ) AS total,
            COUNT(*) FILTER (WHERE v.estado <> 'Completada') AS anuladas
        FROM ventas v
        LEFT JOIN (
            SELECT cod_ven, SUM(total_devuelto) AS devuelto
            FROM devoluciones
            GROUP BY cod_ven
        ) d ON d.cod_ven = v.cod_ven
        WHERE v.fecha BETWEEN %s AND %s
        GROUP BY v.fecha
        ORDER BY v.fecha DESC
    """, (desde, hasta))

    dias = cursor.fetchall()

    mayor = max([d[2] for d in dias], default=0)
    total_periodo = sum(d[2] for d in dias)
    ventas_periodo = sum(d[1] for d in dias)

    return dias, mayor, total_periodo, ventas_periodo



@app.route("/informes")
@admin_required
def informes():
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        # Fecha seleccionada en el formulario
        fecha_seleccionada = request.args.get("fecha", "").strip()

        # Consultar ventas
        consulta_ventas = """
            SELECT
                v.cod_ven,
                v.fecha,
                c.nom_cli,
                u.nom_usu,
                v.total,
                v.estado,
                c.email_cli
            FROM ventas v
            INNER JOIN clientes c
                ON v.cod_cli = c.cod_cli
            INNER JOIN usuarios u
                ON v.cod_usu = u.cod_usu
        """

        if fecha_seleccionada:
            consulta_ventas += """
                WHERE v.fecha::date = %s
            """
            cursor.execute(
                consulta_ventas + " ORDER BY v.cod_ven DESC",
                (fecha_seleccionada,)
            )
        else:
            cursor.execute(
                consulta_ventas + " ORDER BY v.cod_ven DESC"
            )

        ventas = cursor.fetchall()

        # Resumen de ventas por día
        desde, hasta = rango_fechas_informe(cursor)
        dias, mayor_dia, total_periodo, ventas_periodo = consultar_ventas_por_dia(
            cursor, desde, hasta
        )

        # Alertas de inventario
        bajo_stock = consultar_bajo_stock(cursor)
        por_vencer = consultar_lotes_por_vencer()

        # Cantidad de ventas
        cursor.execute("SELECT COUNT(*) FROM ventas")
        total_ventas = cursor.fetchone()[0]

        # Valor total vendido
        cursor.execute("""
            SELECT COALESCE(SUM(v.total - COALESCE(d.devuelto, 0)), 0)
            FROM ventas v
            LEFT JOIN (
                SELECT cod_ven, SUM(total_devuelto) AS devuelto
                FROM devoluciones
                GROUP BY cod_ven
            ) d ON d.cod_ven = v.cod_ven
            WHERE v.estado = 'Completada'
        """)
        valor_total = cursor.fetchone()[0]

        # Bodegas activas
        cursor.execute("""
            SELECT cod_bod, nom_bod
            FROM bodegas
            WHERE estado = 'Activo'
            ORDER BY nom_bod
        """)
        bodegas = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "informes/lista.html",
        ventas=ventas,
        fecha_seleccionada=fecha_seleccionada,
        bajo_stock=bajo_stock,
        por_vencer=por_vencer,
        dias_alerta=DIAS_ALERTA_VENCIMIENTO,
        total_ventas=total_ventas,
        valor_total=valor_total,
        dias=dias,
        mayor_dia=mayor_dia,
        total_periodo=total_periodo,
        ventas_periodo=ventas_periodo,
        desde=desde,
        hasta=hasta,
        bodegas=bodegas,
        productos=[],
        bodega_id=None,
        mostrar_inventario=False
    )



# =========================
# INFORME DE INVENTARIO
# =========================

@app.route("/informes/inventario")
@admin_required
def informe_inventario():
    bodega_id = request.args.get("bodega", type=int)

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        # Consultar las bodegas activas
        cursor.execute("""
            SELECT cod_bod, nom_bod
            FROM bodegas
            WHERE estado = 'Activo'
            ORDER BY nom_bod ASC
        """)
        bodegas = cursor.fetchall()

        # Inicializar la lista de productos
        productos = []

        # Consultar el inventario solo cuando se elija una bodega
        if bodega_id is not None:
            cursor.execute("""
                SELECT
                    p.nom_prod,
                    COALESCE(SUM(l.cantidad_disponible), 0) AS existencia,
                    p.unidad_medida,
                    COALESCE(
                        STRING_AGG(
                            DISTINCT pr.nom_prov,
                            ', ' ORDER BY pr.nom_prov
                        ),
                        '-'
                    ) AS proveedores,
                    p.stock_actual AS total_negocio
                FROM productos p

                LEFT JOIN lotes_producto l
                    ON l.cod_prod = p.cod_prod
                    AND l.ubicacion_bodega = %s
                    AND l.estado = 'Activo'

                LEFT JOIN proveedores pr
                    ON pr.cod_prov = l.cod_prov

                WHERE p.estado = 'Activo'

                GROUP BY
                    p.cod_prod,
                    p.nom_prod,
                    p.unidad_medida,
                    p.stock_actual

                ORDER BY p.nom_prod ASC
            """, (bodega_id,))

            productos = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "informes/informe_inventario.html",
        bodegas=bodegas,
        productos=productos,
        bodega_id=bodega_id
    )


# =========================
# INVENTARIO - CONSULTAR (administrador y vendedor)
# =========================

@app.route("/inventario/consultar")
@login_required
def consultar_inventario():
    q = request.args.get("q", "").strip()

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                p.nom_prod,
                p.unidad_medida,
                p.stock_actual,
                COALESCE(se.stock_minimo, 5),
                COALESCE((
                    SELECT STRING_AGG(
                        x.nom_bod || ': ' || x.cant::text,
                        ' · ' ORDER BY x.nom_bod
                    )
                    FROM (
                        SELECT b.nom_bod, SUM(l.cantidad_disponible) AS cant
                        FROM lotes_producto l
                        INNER JOIN bodegas b
                            ON b.cod_bod = l.ubicacion_bodega
                        WHERE l.cod_prod = p.cod_prod
                          AND l.estado = 'Activo'
                          AND l.cantidad_disponible > 0
                        GROUP BY b.nom_bod
                    ) x
                ), '')
            FROM productos p
            LEFT JOIN stock_en se
                ON se.cod_prod = p.cod_prod
            WHERE p.estado = 'Activo'
              AND (
                    %s = ''
                    OR LOWER(p.nom_prod) LIKE LOWER(%s)
                    OR p.codigo_barras LIKE %s
                  )
            ORDER BY p.nom_prod
        """, (q, "%" + q + "%", "%" + q + "%"))

        productos_inv = cursor.fetchall()
        bajo_stock = consultar_bajo_stock(cursor)

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "inventario/consulta.html",
        productos=productos_inv,
        bajo_stock=bajo_stock,
        por_vencer=consultar_lotes_por_vencer(),
        q=q
    )


# =========================
# VENTAS - HISTORIAL, CORRECCIÓN, ANULACIÓN Y DEVOLUCIONES
# El administrador ve todas las ventas; el vendedor, solo las suyas.
# =========================

class ErrorDeNegocio(Exception):
    """Error cuyo mensaje se le puede mostrar tal cual al usuario."""


def es_administrador():
    return session.get("rol") == "Administrador"


def volver_a_ventas():
    """Administrador: historial de ventas. Empleado: punto de venta."""
    return url_for("historial_ventas" if es_administrador() else "ventas")


def leer_motivo():
    """Motivo escrito en el formulario (de 5 a 200 caracteres), o None."""
    motivo = " ".join(request.form.get("motivo", "").split())

    if len(motivo) < 5 or len(motivo) > 200:
        return None

    return motivo


def cargar_venta(cursor, cod_ven, bloquear=False):
    """
    Devuelve la venta como tupla:
    (cod_ven, fecha, total, estado, cod_cli, nom_cli, cod_usu, nom_usu,
     motivo_anulacion, fecha_anulacion)
    o None si no existe o el vendedor no es quien la hizo.
    """
    consulta = """
        SELECT
            v.cod_ven,
            v.fecha,
            v.total,
            v.estado,
            v.cod_cli,
            c.nom_cli,
            v.cod_usu,
            u.nom_usu,
            v.motivo_anulacion,
            v.fecha_anulacion
        FROM ventas v
        INNER JOIN clientes c
            ON c.cod_cli = v.cod_cli
        INNER JOIN usuarios u
            ON u.cod_usu = v.cod_usu
        WHERE v.cod_ven = %s
    """

    if bloquear:
        consulta += " FOR UPDATE OF v"

    cursor.execute(consulta, (cod_ven,))
    venta = cursor.fetchone()

    if venta is None:
        return None

    if not es_administrador() and venta[6] != session.get("cod_usu"):
        return None

    return venta


def reponer_existencias(cursor, cod_prod, cod_lote, cantidad):
    """Devuelve unidades al inventario (al lote de origen, si lo tiene)."""
    if cod_lote is not None:
        cursor.execute("""
            UPDATE lotes_producto
            SET cantidad_disponible = cantidad_disponible + %s
            WHERE cod_lote = %s
        """, (cantidad, cod_lote))

    mover_stock(cursor, cod_prod, cantidad)

    sincronizar_stock_en(cursor, cod_prod)


@app.route("/ventas/historial")
@admin_required
def historial_ventas():
    q = request.args.get("q", "").strip()

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        cursor.execute("""
            SELECT
                v.cod_ven,
                v.fecha,
                c.nom_cli,
                u.nom_usu,
                v.total,
                v.estado,
                COALESCE(d.devuelto, 0)
            FROM ventas v
            INNER JOIN clientes c
                ON c.cod_cli = v.cod_cli
            INNER JOIN usuarios u
                ON u.cod_usu = v.cod_usu
            LEFT JOIN (
                SELECT cod_ven, SUM(total_devuelto) AS devuelto
                FROM devoluciones
                GROUP BY cod_ven
            ) d ON d.cod_ven = v.cod_ven
            WHERE (%s OR v.cod_usu = %s)
              AND (
                    %s = ''
                    OR v.cod_ven::text = %s
                    OR LOWER(c.nom_cli) LIKE LOWER(%s)
                  )
            ORDER BY v.cod_ven DESC
            LIMIT 200
        """, (
            es_administrador(),
            session.get("cod_usu"),
            q,
            q,
            "%" + q + "%"
        ))

        lista = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "ventas/historial.html",
        ventas=lista,
        q=q,
        es_admin=es_administrador()
    )


@app.route("/ventas/<int:cod_ven>")
@login_required
def detalle_venta(cod_ven):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        venta = cargar_venta(cursor, cod_ven)

        if venta is None:
            flash("Esa venta no existe o no es una de tus ventas.", "warning")
            return redirect(volver_a_ventas())

        cursor.execute("""
            SELECT
                d.cod_detalle,
                p.nom_prod,
                p.unidad_medida,
                COALESCE(l.lote, 'Sin lote'),
                d.cantidad,
                d.descuento,
                d.subtotal,
                COALESCE(dd.cantidad, 0)
            FROM detalle_venta d
            INNER JOIN productos p
                ON p.cod_prod = d.cod_prod
            LEFT JOIN lotes_producto l
                ON l.cod_lote = d.cod_lote
            LEFT JOIN (
                SELECT cod_detalle, SUM(cantidad) AS cantidad
                FROM detalle_devolucion
                GROUP BY cod_detalle
            ) dd ON dd.cod_detalle = d.cod_detalle
            WHERE d.cod_ven = %s
            ORDER BY d.cod_detalle
        """, (cod_ven,))

        renglones = [
            {
                "cod_detalle": f[0],
                "producto": f[1],
                "unidad": f[2],
                "lote": f[3],
                "cantidad": f[4],
                "descuento": f[5],
                "subtotal": f[6],
                "devuelto": f[7],
                "disponible": f[4] - f[7]
            }
            for f in cursor.fetchall()
        ]

        cursor.execute("""
            SELECT
                dv.cod_dev,
                dv.fecha,
                u.nom_usu,
                dv.motivo,
                dv.total_devuelto
            FROM devoluciones dv
            INNER JOIN usuarios u
                ON u.cod_usu = dv.cod_usu
            WHERE dv.cod_ven = %s
            ORDER BY dv.cod_dev
        """, (cod_ven,))

        devoluciones = cursor.fetchall()

        cursor.execute("""
            SELECT cod_cli, nom_cli
            FROM clientes
            ORDER BY nom_cli
        """)

        clientes_lista = cursor.fetchall()

    finally:
        cursor.close()
        conexion.close()

    return render_template(
        "ventas/detalle.html",
        venta=venta,
        renglones=renglones,
        devoluciones=devoluciones,
        total_devuelto=sum((d[4] for d in devoluciones), Decimal("0")),
        clientes=clientes_lista
    )


@app.route("/ventas/<int:cod_ven>/cliente", methods=["POST"])
@login_required
def corregir_cliente_venta(cod_ven):
    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        try:
            cod_cli = int(request.form.get("cod_cli", ""))
        except ValueError:
            raise ErrorDeNegocio("Elige un cliente válido.")

        venta = cargar_venta(cursor, cod_ven, bloquear=True)

        if venta is None:
            flash("Esa venta no existe o no es una de tus ventas.", "warning")
            return redirect(volver_a_ventas())

        if venta[3] != "Completada":
            raise ErrorDeNegocio("Una venta anulada no se puede modificar.")

        cursor.execute(
            "SELECT 1 FROM clientes WHERE cod_cli = %s", (cod_cli,)
        )

        if cursor.fetchone() is None:
            raise ErrorDeNegocio("El cliente elegido no existe.")

        cursor.execute(
            "UPDATE ventas SET cod_cli = %s WHERE cod_ven = %s",
            (cod_cli, cod_ven)
        )

        conexion.commit()
        flash("Cliente de la venta corregido correctamente.", "success")

    except ErrorDeNegocio as error:
        conexion.rollback()
        flash(str(error), "danger")

    except Exception as error:
        conexion.rollback()
        print("ERROR AL CORREGIR EL CLIENTE DE LA VENTA:", repr(error))
        flash("No se pudo corregir la venta.", "danger")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("detalle_venta", cod_ven=cod_ven))


@app.route("/ventas/<int:cod_ven>/anular", methods=["POST"])
@login_required
def anular_venta(cod_ven):
    motivo = leer_motivo()

    if motivo is None:
        flash(
            "Escribe el motivo de la anulación (entre 5 y 200 caracteres).",
            "danger"
        )
        return redirect(url_for("detalle_venta", cod_ven=cod_ven))

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        venta = cargar_venta(cursor, cod_ven, bloquear=True)

        if venta is None:
            flash("Esa venta no existe o no es una de tus ventas.", "warning")
            return redirect(volver_a_ventas())

        if venta[3] != "Completada":
            raise ErrorDeNegocio("Esta venta ya estaba anulada.")

        # Se devuelve al inventario solo lo que aún no se había devuelto.
        cursor.execute("""
            SELECT
                d.cod_prod,
                d.cod_lote,
                d.cantidad - COALESCE(dd.cantidad, 0)
            FROM detalle_venta d
            LEFT JOIN (
                SELECT cod_detalle, SUM(cantidad) AS cantidad
                FROM detalle_devolucion
                GROUP BY cod_detalle
            ) dd ON dd.cod_detalle = d.cod_detalle
            WHERE d.cod_ven = %s
            ORDER BY d.cod_prod, d.cod_detalle
        """, (cod_ven,))

        for cod_prod, cod_lote, restante in cursor.fetchall():
            if restante > 0:
                reponer_existencias(cursor, cod_prod, cod_lote, restante)

        cursor.execute("""
            UPDATE ventas
            SET estado = 'Anulada',
                motivo_anulacion = %s,
                fecha_anulacion = CURRENT_TIMESTAMP,
                cod_usu_anula = %s
            WHERE cod_ven = %s
        """, (motivo, session.get("cod_usu"), cod_ven))

        conexion.commit()
        flash(
            "Venta " + ("%06d" % cod_ven) + " anulada. "
            "Los productos volvieron al inventario.",
            "success"
        )

    except ErrorDeNegocio as error:
        conexion.rollback()
        flash(str(error), "danger")

    except Exception as error:
        conexion.rollback()
        print("ERROR AL ANULAR LA VENTA:", repr(error))
        flash("No se pudo anular la venta.", "danger")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("detalle_venta", cod_ven=cod_ven))


@app.route("/ventas/<int:cod_ven>/devolucion", methods=["POST"])
@login_required
def registrar_devolucion(cod_ven):
    motivo = leer_motivo()

    if motivo is None:
        flash(
            "Escribe el motivo de la devolución (entre 5 y 200 caracteres).",
            "danger"
        )
        return redirect(url_for("detalle_venta", cod_ven=cod_ven))

    conexion = obtener_conexion()
    cursor = conexion.cursor()

    try:
        venta = cargar_venta(cursor, cod_ven, bloquear=True)

        if venta is None:
            flash("Esa venta no existe o no es una de tus ventas.", "warning")
            return redirect(volver_a_ventas())

        if venta[3] != "Completada":
            raise ErrorDeNegocio(
                "No se puede devolver productos de una venta anulada."
            )

        cursor.execute("""
            SELECT
                d.cod_detalle,
                d.cod_prod,
                d.cod_lote,
                d.cantidad,
                d.subtotal,
                COALESCE(dd.cantidad, 0),
                COALESCE(dd.valor, 0)
            FROM detalle_venta d
            LEFT JOIN (
                SELECT
                    cod_detalle,
                    SUM(cantidad) AS cantidad,
                    SUM(valor) AS valor
                FROM detalle_devolucion
                GROUP BY cod_detalle
            ) dd ON dd.cod_detalle = d.cod_detalle
            WHERE d.cod_ven = %s
            ORDER BY d.cod_detalle
        """, (cod_ven,))

        pedidas = []

        for (cod_detalle, cod_prod, cod_lote, vendida,
             subtotal, ya_cantidad, ya_valor) in cursor.fetchall():

            texto = request.form.get("cant_" + str(cod_detalle), "").strip()

            if texto == "":
                continue

            try:
                cantidad = int(texto)
            except ValueError:
                raise ErrorDeNegocio("Las cantidades a devolver no son válidas.")

            if cantidad < 0:
                raise ErrorDeNegocio("Las cantidades a devolver no son válidas.")

            if cantidad == 0:
                continue

            restante = vendida - ya_cantidad

            if cantidad > restante:
                raise ErrorDeNegocio(
                    "No puedes devolver más de lo que se vendió "
                    "(máximo " + str(restante) + " en ese renglón)."
                )

            if cantidad == restante:
                # Lo que quedaba por devolver, sin perder centavos.
                valor = Decimal(subtotal) - Decimal(ya_valor)
            else:
                valor = (
                    Decimal(subtotal) * cantidad / vendida
                ).quantize(CENTAVOS, rounding=ROUND_HALF_UP)

            pedidas.append((cod_detalle, cod_prod, cod_lote, cantidad, valor))

        if not pedidas:
            raise ErrorDeNegocio(
                "Indica la cantidad de al menos un producto a devolver."
            )

        total_devuelto = sum((p[4] for p in pedidas), Decimal("0"))

        cursor.execute("""
            INSERT INTO devoluciones (cod_ven, cod_usu, motivo, total_devuelto)
            VALUES (%s, %s, %s, %s)
            RETURNING cod_dev
        """, (cod_ven, session.get("cod_usu"), motivo, total_devuelto))

        cod_dev = cursor.fetchone()[0]

        for cod_detalle, cod_prod, cod_lote, cantidad, valor in pedidas:
            cursor.execute("""
                INSERT INTO detalle_devolucion
                (cod_dev, cod_detalle, cantidad, valor)
                VALUES (%s, %s, %s, %s)
            """, (cod_dev, cod_detalle, cantidad, valor))

            reponer_existencias(cursor, cod_prod, cod_lote, cantidad)

        conexion.commit()
        flash(
            "Devolución registrada por ${:,.0f}. "
            "Los productos volvieron al inventario.".format(total_devuelto),
            "success"
        )

    except ErrorDeNegocio as error:
        conexion.rollback()
        flash(str(error), "danger")

    except Exception as error:
        conexion.rollback()
        print("ERROR AL REGISTRAR LA DEVOLUCIÓN:", repr(error))
        flash("No se pudo registrar la devolución.", "danger")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for("detalle_venta", cod_ven=cod_ven))


# =========================
# EJECUTAR FLASK
# =========================

if __name__ == "__main__":
    app.run(debug=True)