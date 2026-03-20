# ==========================================
# 1. IMPORTACIONES Y EXPLICACIÓN
# ==========================================
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL             # Conector para comunicarse con la base de datos MySQL
import MySQLdb.cursors                      # Permite manejar los datos como diccionarios (llave-valor)
from functools import wraps                 # Herramienta para crear decoradores sin perder metadatos
from werkzeug.security import check_password_hash, generate_password_hash # Cifrado de seguridad
from datetime import date                   # Para capturar la fecha actual en inscripciones
from flask_mail import Mail, Message        # Para el envío de correos electrónicos (MFA)
import random                               # Generador de números aleatorios para el código 2FA
import string                               # Provee caracteres para construir el código de seguridad
import re                                   # Expresiones regulares para validar la fuerza de la clave

app = Flask(__name__)
app.secret_key = "miClaveSegura" # Llave para cifrar las sesiones del navegador

# ==========================================
# 2. CONFIGURACIÓN DE SERVICIOS
# ==========================================

# Configuración para Gmail (Envío de códigos)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'jorge61162559@gmail.com'
app.config['MAIL_PASSWORD'] = 'ebrqsslpuzfoxfjy' 
mail = Mail(app)

# Configuración de Base de Datos
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'universidad_sistema' 
conexion = MySQL(app)

# ==========================================
# 3. FUNCIONES DE APOYO Y DECORADORES
# ==========================================

# Validador de complejidad de contraseña
def es_password_fuerte(password):
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "Debe incluir al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return False, "Debe incluir al menos una letra minúscula."
    if not re.search(r"\d", password):
        return False, "Debe incluir al menos un número."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Debe incluir al menos un carácter especial (!@#$)."
    return True, "Contraseña fuerte."

# Decorador para restringir acceso si no hay sesión
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped_view

# Decorador para restringir acceso según el ROL (Admin, Operador, etc.)
def role_required(roles_permitidos):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if session.get('rol') not in roles_permitidos:
                flash("No tienes permisos suficientes para realizar esta acción.", "danger")
                return redirect(url_for('index'))
            return view(*args, **kwargs)
        return wrapped_view
    return decorator

# ==========================================
# 4. RUTAS DE AUTENTICACIÓN
# ==========================================

@app.route("/registro", methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        usuario = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        valido, mensaje = es_password_fuerte(password)
        if not valido:
            flash(mensaje, "danger")
            return render_template("registro.html")

        pass_hashed = generate_password_hash(password)
        cursor = conexion.connection.cursor()
        cursor.execute("INSERT INTO usuarios (username, password_hash, email, rol) VALUES (%s, %s, %s, %s)", 
                       (usuario, pass_hashed, email, 'user')) 
        conexion.connection.commit()
        cursor.close()
        
        flash("¡Registro exitoso! Ahora puedes iniciar sesión.", "success")
        return redirect(url_for('login'))
    return render_template("registro.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nom_usuario = request.form["usuario"]
        password = request.form["password"]
        cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
        
        cursor.execute("SELECT * FROM usuarios WHERE username = %s", (nom_usuario,))
        usuario = cursor.fetchone()

        if usuario and check_password_hash(usuario["password_hash"], password):
            codigo = ''.join(random.choices(string.digits, k=6))
            cursor.execute("UPDATE usuarios SET codigo_verificacion = %s WHERE id = %s", (codigo, usuario['id']))
            conexion.connection.commit()

            try:
                msg = Message('Código de Verificación - Sistema U', 
                              sender=app.config['MAIL_USERNAME'], 
                              recipients=[usuario['email']])
                msg.body = f"Tu código de acceso es: {codigo}"
                mail.send(msg)
                session['auth_user_id'] = usuario['id']
                return redirect(url_for('segundo_factor'))
            except Exception as e:
                flash("Error al enviar el correo.", "danger")
        
        flash("Usuario o contraseña incorrectos", "danger")
    return render_template("login.html")

@app.route("/verificar-codigo", methods=["GET", "POST"])
def segundo_factor():
    if 'auth_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        codigo_ingresado = request.form["codigo"]
        user_id = session['auth_user_id']
        
        cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM usuarios WHERE id = %s", (user_id,))
        usuario = cursor.fetchone()

        if usuario['codigo_verificacion'] == codigo_ingresado:
            session.clear()
            session['user_id'] = usuario['id']
            session['username'] = usuario['username']
            session['rol'] = usuario['rol']
            
            cursor.execute("UPDATE usuarios SET codigo_verificacion = NULL WHERE id = %s", (user_id,))
            conexion.connection.commit()
            return redirect(url_for('index'))
        else:
            flash("Código de verificación incorrecto.", "danger")
            
    return render_template("verificar.html")

@app.route("/logout")
def logout():
    if 'username' in session:
        cursor = conexion.connection.cursor()
        cursor.execute("INSERT INTO historial_accesos (usuario_intentado, evento, resultado) VALUES (%s, %s, %s)", 
                       (session['username'], "Cerró sesión", "Válido"))
        conexion.connection.commit()
        cursor.close()
    session.clear()
    return redirect(url_for("login"))

# ==========================================
# 5. ADMINISTRACIÓN Y USUARIOS
# ==========================================

@app.route("/")
@login_required
def index():
    return render_template("inicio.html")

@app.route("/admin/usuarios")
@login_required
@role_required(['admin'])
def gestionar_usuarios():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, username, email, rol FROM usuarios")
    lista = cursor.fetchall()
    cursor.close()
    return render_template("usuarios.html", lista_usuarios=lista)

@app.route("/admin/usuarios/nuevo", methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def nuevo_usuario_admin():
    if request.method == 'POST':
        user = request.form['username']
        email = request.form['email']
        passw = request.form['password']
        rol = request.form['rol']
        
        es_valida, mensaje = es_password_fuerte(passw)
        if not es_valida:
            flash(mensaje, "danger")
            return render_template("formulario_usuario.html")

        hashed = generate_password_hash(passw)
        cursor = conexion.connection.cursor()
        cursor.execute("INSERT INTO usuarios (username, email, password_hash, rol) VALUES (%s, %s, %s, %s)", 
                       (user, email, hashed, rol))
        conexion.connection.commit()
        cursor.close()
        flash("Usuario creado con éxito", "success")
        return redirect(url_for('gestionar_usuarios'))
    return render_template("formulario_usuario.html")

@app.route("/admin/usuarios/editar/<int:id>", methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def editar_usuario(id):
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        nuevo_rol = request.form['rol']
        nuevo_email = request.form['email']
        
        # Primero obtenemos el nombre del usuario afectado para que el log sea claro
        cursor.execute("SELECT username FROM usuarios WHERE id = %s", (id,))
        usuario_afectado = cursor.fetchone()
        nombre_afectado = usuario_afectado['username'] if usuario_afectado else str(id)

        # Actualizamos al usuario
        cursor.execute("UPDATE usuarios SET rol=%s, email=%s WHERE id=%s", (nuevo_rol, nuevo_email, id))
        
        # --- ESTO ES LO QUE FALTA PARA TU TABLA DE LOGS ---
        evento_descripcion = f"Modificó al usuario: {nombre_afectado} (Rol: {nuevo_rol})"
        cursor.execute("INSERT INTO historial_accesos (usuario_intentado, evento, resultado) VALUES (%s, %s, %s)", 
                       (session['username'], evento_descripcion, "Válido"))
        
        conexion.connection.commit()
        cursor.close()
        flash("Cambios guardados y registrados en el historial.", "success")
        return redirect(url_for('gestionar_usuarios'))
    
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    u = cursor.fetchone()
    cursor.close()
    return render_template("editar_usuario.html", u=u)

@app.route("/admin/usuarios/eliminar/<int:id>")
@login_required
@role_required(['admin'])
def eliminar_usuario(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    flash("Usuario eliminado", "warning")
    return redirect(url_for('gestionar_usuarios'))

@app.route("/admin/historial")
@login_required
@role_required(['admin', 'auditor'])
def ver_historial():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM historial_accesos ORDER BY fecha_hora DESC")
    logs = cursor.fetchall()
    cursor.close()
    return render_template("historial.html", logs=logs)

# ==========================================
# 6. GESTIÓN ACADÉMICA (CRUDs)
# ==========================================

# --- ESTUDIANTES ---
@app.route("/estudiantes")
@login_required
def mostrar_estudiantes():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("INSERT INTO historial_accesos (usuario_intentado, evento, resultado) VALUES (%s, %s, %s)", 
                   (session['username'], "Visualizó lista de estudiantes", "Válido"))
    cursor.execute("SELECT * FROM estudiantes")
    estudiantes = cursor.fetchall()
    conexion.connection.commit()
    cursor.close()
    return render_template("estudiantes.html", estudiantes=estudiantes)

@app.route("/estudiantes/nuevo", methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def nuevo_estudiante():
    if request.method == 'POST':
        nombre, apellido = request.form['nombre'], request.form['apellido']
        datos = (nombre, apellido, request.form['carrera'], request.form['email'], request.form['telefono'])
        cursor = conexion.connection.cursor()
        cursor.execute("INSERT INTO estudiantes (nombre, apellido, carrera, email, telefono) VALUES (%s,%s,%s,%s,%s)", datos)
        cursor.execute("INSERT INTO historial_accesos (usuario_intentado, evento, resultado) VALUES (%s, %s, %s)", 
                       (session['username'], f"Creó al estudiante: {nombre} {apellido}", "Válido"))
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_estudiantes'))
    return render_template("formulario_estudiante.html")

@app.route("/estudiantes/modificar/<int:id>", methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'operador'])
def modificar_estudiante(id):
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        datos = (request.form['nombre'], request.form['apellido'], request.form['carrera'], request.form['email'], request.form['telefono'], id)
        cursor.execute("UPDATE estudiantes SET nombre=%s, apellido=%s, carrera=%s, email=%s, telefono=%s WHERE id_estudiante=%s", datos)
        cursor.execute("INSERT INTO historial_accesos (usuario_intentado, evento, resultado) VALUES (%s, %s, %s)", 
                       (session['username'], f"Modificó al estudiante ID {id}", "Válido"))
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_estudiantes'))
    else:
        cursor.execute("SELECT * FROM estudiantes WHERE id_estudiante = %s", (id,))
        estudiante = cursor.fetchone()
        cursor.close()
        return render_template("formulario_modificar_estudiante.html", estudiante=estudiante)

@app.route("/estudiantes/eliminar/<int:id>")
@login_required
@role_required(['admin'])
def eliminar_estudiante(id):
    cursor = conexion.connection.cursor()
    cursor.execute("INSERT INTO historial_accesos (usuario_intentado, evento, resultado) VALUES (%s, %s, %s)", 
                   (session['username'], f"Eliminó al estudiante ID {id}", "Válido"))
    cursor.execute("DELETE FROM estudiantes WHERE id_estudiante = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_estudiantes'))

# --- DOCENTES ---
@app.route("/docentes")
@login_required
def mostrar_docentes():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM docentes")
    docentes = cursor.fetchall()
    cursor.close()
    return render_template("docentes.html", docentes=docentes)

@app.route("/docentes/nuevo", methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def nuevo_docente():
    if request.method == 'POST':
        nombre, apellido = request.form['nombre'], request.form['apellido']
        datos = (nombre, apellido, request.form['especialidad'], request.form['email'])
        cursor = conexion.connection.cursor()
        cursor.execute("INSERT INTO docentes (nombre, apellido, especialidad, email) VALUES (%s,%s,%s,%s)", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_docentes'))
    return render_template("formulario_docente.html")

@app.route("/docentes/modificar/<int:id>", methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'operador'])
def modificar_docente(id):
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        datos = (request.form['nombre'], request.form['apellido'], request.form['especialidad'], request.form['email'], id)
        cursor.execute("UPDATE docentes SET nombre=%s, apellido=%s, especialidad=%s, email=%s WHERE id_docente=%s", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_docentes'))
    else:
        cursor.execute("SELECT * FROM docentes WHERE id_docente = %s", (id,))
        docente = cursor.fetchone()
        cursor.close()
        return render_template("formulario_modificar_docente.html", docente=docente)

@app.route("/docentes/eliminar/<int:id>")
@login_required
@role_required(['admin'])
def eliminar_docente(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM docentes WHERE id_docente = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_docentes'))

# --- AULAS ---
@app.route("/aulas")
@login_required
def mostrar_aulas():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM aulas")
    aulas = cursor.fetchall()
    cursor.close()
    return render_template("aulas.html", aulas=aulas)

@app.route("/aulas/nuevo", methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def nueva_aula():
    if request.method == 'POST':
        datos = (request.form['nombre_aula'], request.form['capacidad'], request.form['ubicacion'])
        cursor = conexion.connection.cursor()
        cursor.execute("INSERT INTO aulas (nombre_aula, capacidad, ubicacion) VALUES (%s,%s,%s)", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_aulas'))
    return render_template("formulario_aula.html")

@app.route("/aulas/modificar/<int:id>", methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'operador'])
def modificar_aula(id):
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        datos = (request.form['nombre_aula'], request.form['capacidad'], request.form['ubicacion'], id)
        cursor.execute("UPDATE aulas SET nombre_aula=%s, capacidad=%s, ubicacion=%s WHERE id_aula=%s", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_aulas'))
    else:
        cursor.execute("SELECT * FROM aulas WHERE id_aula = %s", (id,))
        aula = cursor.fetchone()
        cursor.close()
        return render_template("formulario_modificar_aula.html", aula=aula)

@app.route("/aulas/eliminar/<int:id>")
@login_required
@role_required(['admin'])
def eliminar_aula(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM aulas WHERE id_aula = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_aulas'))

# --- MATERIAS ---
@app.route("/materias")
@login_required
def mostrar_materias():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    sql = """
    SELECT m.id_materia, m.nombre_materia, m.sigla, 
            d.nombre AS doc_nombre, d.apellido AS doc_apellido, 
            a.nombre_aula AS aula 
    FROM materias m
    LEFT JOIN docentes d ON m.id_docente = d.id_docente
    LEFT JOIN aulas a ON m.id_aula = a.id_aula
    """
    cursor.execute(sql)
    materias = cursor.fetchall()
    cursor.close()
    return render_template("materias.html", materias=materias)

@app.route("/materias/nuevo", methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def nueva_materia():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        datos = (request.form['nombre'], request.form['sigla'], request.form['id_docente'], request.form['id_aula'])
        cursor.execute("INSERT INTO materias (nombre_materia, sigla, id_docente, id_aula) VALUES (%s,%s,%s,%s)", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_materias'))
    else:
        cursor.execute("SELECT id_docente, nombre FROM docentes")
        docentes = cursor.fetchall()
        cursor.execute("SELECT id_aula, nombre_aula FROM aulas")
        aulas = cursor.fetchall()
        cursor.close()
        return render_template("formulario_materia.html", docentes=docentes, aulas=aulas)
    
@app.route("/materias/modificar/<int:id>", methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'operador'])
def modificar_materia(id):
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        datos = (request.form['nombre'], request.form['sigla'], request.form['id_docente'], request.form['id_aula'], id)
        cursor.execute("UPDATE materias SET nombre_materia=%s, sigla=%s, id_docente=%s, id_aula=%s WHERE id_materia=%s", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_materias'))
    else:
        cursor.execute("SELECT * FROM materias WHERE id_materia = %s", (id,))
        materia = cursor.fetchone()
        cursor.execute("SELECT id_docente, nombre FROM docentes")
        docentes = cursor.fetchall()
        cursor.execute("SELECT id_aula, nombre_aula FROM aulas")
        aulas = cursor.fetchall()
        cursor.close()
        return render_template("formulario_modificar_materia.html", materia=materia, docentes=docentes, aulas=aulas)

@app.route("/materias/eliminar/<int:id>")
@login_required
@role_required(['admin'])
def eliminar_materia(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM materias WHERE id_materia = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_materias'))

# --- INSCRIPCIONES ---
@app.route("/inscripciones")
@login_required
def mostrar_inscripciones():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    sql = """
    SELECT i.id_inscripcion, 
            e.nombre AS est_nombre, e.apellido AS est_apellido, 
            m.nombre_materia, i.fecha_inscripcion
    FROM inscripciones i
    JOIN estudiantes e ON i.id_estudiante = e.id_estudiante
    JOIN materias m ON i.id_materia = m.id_materia
    """
    cursor.execute(sql)
    inscripciones = cursor.fetchall()
    cursor.close()
    return render_template("inscripciones.html", inscripciones=inscripciones)

@app.route("/inscripciones/nuevo", methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def nueva_inscripcion():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        id_est = request.form['id_estudiante']
        id_mat = request.form['id_materia']
        fecha_actual = date.today()
        cursor.execute("INSERT INTO inscripciones (id_estudiante, id_materia, fecha_inscripcion) VALUES (%s,%s,%s)", (id_est, id_mat, fecha_actual))
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_inscripciones'))
    else:
        cursor.execute("SELECT id_estudiante, nombre FROM estudiantes")
        estudiantes = cursor.fetchall()
        cursor.execute("SELECT id_materia, nombre_materia FROM materias")
        materias = cursor.fetchall()
        cursor.close()
        return render_template("formulario_inscripcion.html", estudiantes=estudiantes, materias=materias)
    
@app.route("/inscripciones/modificar/<int:id>", methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'operador'])
def modificar_inscripcion(id):
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        datos = (request.form['id_estudiante'], request.form['id_materia'], id)
        cursor.execute("UPDATE inscripciones SET id_estudiante=%s, id_materia=%s WHERE id_inscripcion=%s", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_inscripciones'))
    else:
        cursor.execute("SELECT * FROM inscripciones WHERE id_inscripcion = %s", (id,))
        inscripcion = cursor.fetchone()
        cursor.execute("SELECT id_estudiante, nombre FROM estudiantes")
        estudiantes = cursor.fetchall()
        cursor.execute("SELECT id_materia, nombre_materia FROM materias")
        materias = cursor.fetchall()
        cursor.close()
        return render_template("formulario_modificar_inscripcion.html", inscripcion=inscripcion, estudiantes=estudiantes, materias=materias)

@app.route("/inscripciones/eliminar/<int:id>")
@login_required
@role_required(['admin'])
def eliminar_inscripcion(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM inscripciones WHERE id_inscripcion = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_inscripciones'))

if __name__ == '__main__':
    app.run(debug=True)