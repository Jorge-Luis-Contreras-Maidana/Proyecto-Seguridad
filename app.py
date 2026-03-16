from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from datetime import date

app = Flask(__name__)
app.secret_key = "universidad_llave_maestra"

# --- CONFIGURACIÓN DE BASE DE DATOS ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'universidad_sistema' 

conexion = MySQL(app)

# ==========================================
# 0. INICIO (INDEX)
# ==========================================
@app.route("/")
def index():
    return render_template("index.html")

# ==========================================
# 1. GESTIÓN DE ESTUDIANTES
# ==========================================
@app.route("/estudiantes")
def mostrar_estudiantes():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM estudiantes")
    estudiantes = cursor.fetchall()
    cursor.close()
    return render_template("estudiantes.html", estudiantes=estudiantes)

@app.route("/estudiantes/nuevo", methods=['GET', 'POST'])
def nuevo_estudiante():
    if request.method == 'POST':
        datos = (request.form['nombre'], request.form['apellido'], request.form['carrera'], request.form['email'], request.form['telefono'])
        cursor = conexion.connection.cursor()
        cursor.execute("INSERT INTO estudiantes (nombre, apellido, carrera, email, telefono) VALUES (%s,%s,%s,%s,%s)", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_estudiantes'))
    return render_template("formulario_estudiante.html")

@app.route("/estudiantes/modificar/<int:id>", methods=['GET', 'POST'])
def modificar_estudiante(id):
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        datos = (request.form['nombre'], request.form['apellido'], request.form['carrera'], request.form['email'], request.form['telefono'], id)
        cursor.execute("UPDATE estudiantes SET nombre=%s, apellido=%s, carrera=%s, email=%s, telefono=%s WHERE id_estudiante=%s", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_estudiantes'))
    else:
        cursor.execute("SELECT * FROM estudiantes WHERE id_estudiante = %s", (id,))
        estudiante = cursor.fetchone()
        cursor.close()
        return render_template("formulario_modificar_estudiante.html", estudiante=estudiante)

@app.route("/estudiantes/eliminar/<int:id>")
def eliminar_estudiante(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM estudiantes WHERE id_estudiante = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_estudiantes'))

# ==========================================
# 2. GESTIÓN DE DOCENTES
# ==========================================
@app.route("/docentes")
def mostrar_docentes():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id_docente, nombre, apellido, especialidad, email FROM docentes")
    docentes = cursor.fetchall()
    cursor.close()
    return render_template("docentes.html", docentes=docentes)

@app.route("/docentes/nuevo", methods=['GET', 'POST'])
def nuevo_docente():
    if request.method == 'POST':
        datos = (request.form['nombre'], request.form['apellido'], request.form['especialidad'], request.form['email'])
        cursor = conexion.connection.cursor()
        cursor.execute("INSERT INTO docentes (nombre, apellido, especialidad, email) VALUES (%s,%s,%s,%s)", datos)
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_docentes'))
    return render_template("formulario_docente.html")

@app.route("/docentes/modificar/<int:id>", methods=['GET', 'POST'])
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
def eliminar_docente(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM docentes WHERE id_docente = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_docentes'))

# ==========================================
# 3. GESTIÓN DE AULAS
# ==========================================
@app.route("/aulas")
def mostrar_aulas():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM aulas")
    aulas = cursor.fetchall()
    cursor.close()
    return render_template("aulas.html", aulas=aulas)

@app.route("/aulas/nuevo", methods=['GET', 'POST'])
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
def eliminar_aula(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM aulas WHERE id_aula = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_aulas'))

# ==========================================
# 4. GESTIÓN DE MATERIAS
# ==========================================
@app.route("/materias")
def mostrar_materias():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    # Usamos CONCAT para unir nombre y apellido
    sql = sql = """
    SELECT m.id_materia, m.nombre_materia, m.sigla, 
           d.nombre AS doc_nombre, d.apellido AS doc_apellido, 
           a.nombre_aula AS aula 
    FROM materias m
    LEFT JOIN docentes d ON m.id_docente = d.id_docente
    LEFT JOIN aulas a ON m.id_aula = a.id_aula
"""
    cursor.execute(sql)
    materias = cursor.fetchall()
    return render_template("materias.html", materias=materias)

@app.route("/materias/nuevo", methods=['GET', 'POST'])
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
def eliminar_materia(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM materias WHERE id_materia = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_materias'))

# ==========================================
# 5. GESTIÓN DE INSCRIPCIONES
# ==========================================
@app.route("/inscripciones")
def mostrar_inscripciones():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    sql = sql = """
    SELECT i.id_inscripcion, 
           e.nombre AS est_nombre, e.apellido AS est_apellido, 
           m.nombre_materia, i.fecha_inscripcion
    FROM inscripciones i
    JOIN estudiantes e ON i.id_estudiante = e.id_estudiante
    JOIN materias m ON i.id_materia = m.id_materia
"""
    cursor.execute(sql)
    inscripciones = cursor.fetchall()
    return render_template("inscripciones.html", inscripciones=inscripciones)

@app.route("/inscripciones/nuevo", methods=['GET', 'POST'])
def nueva_inscripcion():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        id_est = request.form['id_estudiante']
        id_mat = request.form['id_materia']
        fecha = date.today()
        cursor.execute("INSERT INTO inscripciones (id_estudiante, id_materia, fecha_inscripcion) VALUES (%s,%s,%s)", (id_est, id_mat, fecha))
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
def modificar_inscripcion(id):
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
        # Recibir los nuevos IDs del formulario
        id_est = request.form['id_estudiante']
        id_mat = request.form['id_materia']
        
        # Ejecutar la actualización
        sql = "UPDATE inscripciones SET id_estudiante=%s, id_materia=%s WHERE id_inscripcion=%s"
        cursor.execute(sql, (id_est, id_mat, id))
        conexion.connection.commit()
        cursor.close()
        return redirect(url_for('mostrar_inscripciones'))
    
    else:
        # Cargar los datos de la inscripción actual
        cursor.execute("SELECT * FROM inscripciones WHERE id_inscripcion = %s", (id,))
        inscripcion = cursor.fetchone()
        
        # Cargar listas para los select del formulario
        cursor.execute("SELECT id_estudiante, nombre, apellido FROM estudiantes")
        estudiantes = cursor.fetchall()
        
        cursor.execute("SELECT id_materia, nombre_materia FROM materias")
        materias = cursor.fetchall()
        
        cursor.close()
        return render_template("formulario_modificar_inscripcion.html", 
                               inscripcion=inscripcion, 
                               estudiantes=estudiantes, 
                               materias=materias)

@app.route("/inscripciones/eliminar/<int:id>")
def eliminar_inscripcion(id):
    cursor = conexion.connection.cursor()
    cursor.execute("DELETE FROM inscripciones WHERE id_inscripcion = %s", (id,))
    conexion.connection.commit()
    cursor.close()
    return redirect(url_for('mostrar_inscripciones'))

if __name__ == '__main__':
    app.run(debug=True)