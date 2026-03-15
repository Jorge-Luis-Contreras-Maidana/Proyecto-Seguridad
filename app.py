# --- IMPORTS NECESARIOS ---
from flask import Flask, render_template, request, redirect, url_for
from flask_mysqldb import MySQL
import MySQLdb.cursors 

# --- INICIALIZACIÓN ---
app = Flask(__name__)

# --- CONFIGURACIÓN DE BASE DE DATOS ---
# Asegúrate de que el nombre de la base de datos coincida con la que creamos: 'universidad_sistema'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'universidad_sistema' 

conexion = MySQL(app)


# --- RUTA PÚBLICA: LISTAR ESTUDIANTES ---
@app.route("/estudiantes")
def mostrar_estudiantes():
    # Creamos cursor como diccionario para acceder por nombre de columna
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    sql = "SELECT * FROM estudiantes"
    cursor.execute(sql)
    estudiantes = cursor.fetchall()
    cursor.close()
    
    # Esto renderizará un archivo llamado 'estudiantes.html' 
    # que debes tener en tu carpeta 'templates'
    return render_template("estudiantes.html", estudiantes=estudiantes)

# --- RUTA PÚBLICA: LISTAR MATERIAS CON DOCENTE Y AULA ---
@app.route("/materias")
def mostrar_materias():
    cursor = conexion.connection.cursor(MySQLdb.cursors.DictCursor)
    # Hacemos JOIN para traer información relacionada legible
    sql = """
        SELECT m.nombre_materia, m.sigla, d.nombre AS docente, a.nombre_aula AS aula 
        FROM materias m
        LEFT JOIN docentes d ON m.id_docente = d.id_docente
        LEFT JOIN aulas a ON m.id_aula = a.id_aula
    """
    cursor.execute(sql)
    materias = cursor.fetchall()
    cursor.close()
    
    return render_template("materias.html", materias=materias)


if __name__ == '__main__':
    app.run(debug=True)