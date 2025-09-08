import streamlit as st
import pandas as pd
import psycopg2
import google.generativeai as genai
import time
from datetime import datetime
from supabase import create_client, Client

# --- Configuración de la Página ---
st.set_page_config(
    page_title="LegalIA - Sistema de Gestión",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Conexiones a Servicios ---
try:
    # Conexión a Base de Datos PostgreSQL
    DB_CONFIG = st.secrets["database"]
    
    # Configuración de IA de Google Gemini
    AI_CONFIG = st.secrets["ai"]
    genai.configure(api_key=AI_CONFIG['google_api_key'])
    MODELO_IA = genai.GenerativeModel('gemini-1.5-flash')

    # Conexión a Supabase Storage
    SUPABASE_URL = st.secrets["supabase"]["url"]
    SUPABASE_KEY = st.secrets["supabase"]["key"]
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

except (FileNotFoundError, KeyError) as e:
    st.error(f"⚠️ Error de Configuración: Falta una credencial en los secretos de Streamlit: {e}. Revisa tu configuración.")
    st.stop()

BUCKET_NAME = "documentos_casos"

# --- Funciones de Base de Datos ---
@st.cache_resource
def get_db_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        st.error(f"Error al conectar a la base de datos: {e}")
        return None

def fetch_data(query, params=None):
    conn = get_db_connection()
    if conn:
        try:
            return pd.read_sql_query(query, conn, params=params)
        finally:
            # No cerramos la conexión cacheada
            pass
    return pd.DataFrame()

def execute_procedure(procedure_call, params=None):
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute(procedure_call, params)
            conn.commit()
            return True
        except Exception as e:
            st.error(f"Error al ejecutar el procedimiento: {e}")
            return False
    return False

# --- Funciones de IA ---
def resumir_caso_ia(descripcion):
    if not descripcion or not isinstance(descripcion, str) or len(descripcion.strip()) < 10:
        return "Descripción demasiado breve para resumir."
    prompt = f"Actúa como un asistente legal experto. Resume el siguiente caso en un máximo de 3 frases clave. Descripción: '{descripcion}'"
    try:
        with st.spinner("🧠 La IA está analizando el caso..."):
            response = MODELO_IA.generate_content(prompt)
        return response.text
    except Exception as e:
        st.warning(f"No se pudo generar el resumen con IA. Motivo: {e}")
        return "Resumen no disponible."

# --- Módulos de la Interfaz de Usuario (UI) ---

def mostrar_dashboard():
    st.header("📊 Dashboard de Casos")
    casos_df = fetch_data("SELECT * FROM obtener_casos_detallados();")
    if casos_df.empty:
        st.info("No hay casos registrados en el sistema.")
        return

    # ... (código de filtros sin cambios) ...
    termino_busqueda = st.text_input("Buscar por título, descripción, cliente o abogado:", placeholder="Escribe para buscar...")
    casos_filtrados = casos_df
    if termino_busqueda:
        casos_filtrados = casos_filtrados[casos_filtrados.apply(lambda row: termino_busqueda.lower() in str(row).lower(), axis=1)]

    for _, caso in casos_filtrados.iterrows():
        with st.expander(f"**{caso['titulo_caso']}** - Cliente: {caso['cliente']} (Estado: {caso['estado_caso']})"):
            # ... (código de info de caso y acciones sin cambios) ...
            st.markdown(f"**Descripción:**"); st.caption(caso['descripcion_caso'])

            # --- SECCIÓN DE DOCUMENTOS CON DESCARGA REAL ---
            st.divider()
            st.subheader("📄 Documentos del Caso")
            documentos_df = fetch_data("SELECT nombre_archivo, url_almacenamiento as path FROM documentos WHERE caso_id = %s ORDER BY fecha_subida DESC", (caso['id_caso'],))
            
            if documentos_df.empty:
                st.caption("No hay documentos asociados a este caso.")
            else:
                for _, doc in documentos_df.iterrows():
                    try:
                        # Generar URL de descarga segura y temporal (válida por 60 segundos)
                        response = supabase.storage.from_(BUCKET_NAME).create_signed_url(doc['path'], 60)
                        st.markdown(f"- [{doc['nombre_archivo']}]({response['signedURL']})")
                    except Exception as e:
                        st.warning(f"No se pudo generar el enlace para {doc['nombre_archivo']}. Error: {e}")


def mostrar_gestion_documental():
    st.header("📂 Gestión Documental")
    st.info("Sube y asocia documentos a los casos existentes en el sistema.")

    casos_df = fetch_data("SELECT id, titulo FROM casos ORDER BY fecha_apertura DESC;")
    if casos_df.empty:
        st.warning("No hay casos registrados. Por favor, crea un caso antes de subir documentos.")
        return

    casos_map = {row['titulo']: row['id'] for _, row in casos_df.iterrows()}
    caso_seleccionado_titulo = st.selectbox("Paso 1: Selecciona el caso", options=casos_map.keys())
    
    uploaded_file = st.file_uploader("Paso 2: Elige un archivo", type=['pdf', 'docx', 'txt', 'jpg', 'png', 'jpeg'])

    if st.button("Subir y Asociar Documento", disabled=(uploaded_file is None)):
        if caso_seleccionado_titulo and uploaded_file is not None:
            caso_id = casos_map[caso_seleccionado_titulo]
            file_name = uploaded_file.name
            file_type = uploaded_file.type
            file_bytes = uploaded_file.getvalue()
            
            # Crear una ruta única para el archivo en el bucket
            file_path = f"{caso_id}/{int(time.time())}_{file_name}"

            with st.spinner("Subiendo archivo a la nube..."):
                try:
                    # Subir el archivo a Supabase Storage
                    supabase.storage.from_(BUCKET_NAME).upload(
                        file=file_bytes,
                        path=file_path,
                        file_options={"content-type": file_type}
                    )
                    
                    # Registrar la ruta del archivo en la base de datos
                    if execute_procedure("CALL registrar_documento(%s, %s, %s, %s)", (file_name, file_type, caso_id, file_path)):
                        st.success(f"¡Éxito! Documento '{file_name}' subido y asociado al caso '{caso_seleccionado_titulo}'.")
                        st.balloons()
                    
                except Exception as e:
                    st.error(f"Error al subir el archivo: {e}")


# --- Módulos Anteriores (sin cambios significativos) ---
def mostrar_crear_caso():
    st.header("📝 Crear Nuevo Caso")
    clientes_df = fetch_data("SELECT id, nombre, apellido FROM clientes ORDER BY nombre, apellido;")
    abogados_df = fetch_data("SELECT id, nombre, apellido FROM abogados ORDER BY nombre, apellido;")
    if clientes_df.empty or abogados_df.empty:
        st.warning("Debe registrar al menos un cliente y un abogado."); return
    clientes_map = {f"{row['nombre']} {row['apellido']}": row['id'] for _, row in clientes_df.iterrows()}
    abogados_map = {f"{row['nombre']} {row['apellido']}": row['id'] for _, row in abogados_df.iterrows()}
    with st.form("nuevo_caso_form"):
        titulo = st.text_input("Título del Caso")
        descripcion = st.text_area("Descripción")
        cliente_sel = st.selectbox("Cliente", options=clientes_map.keys())
        abogado_sel = st.selectbox("Abogado", options=abogados_map.keys())
        if st.form_submit_button("Registrar Caso"):
            if not titulo: st.error("El título es obligatorio.")
            else:
                if execute_procedure("CALL registrar_nuevo_caso(%s, %s, %s, %s)", (titulo, descripcion, clientes_map[cliente_sel], abogados_map[abogado_sel])):
                    st.success(f"Caso '{titulo}' registrado."); st.balloons()

def mostrar_gestion_entidades():
    st.header("👥 Gestión de Clientes y Abogados")
    tab_clientes, tab_abogados = st.tabs(["Clientes", "Abogados"])
    with tab_clientes:
        with st.form("nuevo_cliente_form", clear_on_submit=True):
            nombre = st.text_input("Nombre")
            apellido = st.text_input("Apellido")
            email = st.text_input("Email")
            if st.form_submit_button("Guardar Cliente"):
                if nombre and apellido and email:
                    if execute_procedure("INSERT INTO clientes (nombre, apellido, email) VALUES (%s, %s, %s)",(nombre, apellido, email)):
                        st.success(f"Cliente guardado."); st.rerun()
                else: st.error("Nombre, Apellido y Email son obligatorios.")
        st.dataframe(fetch_data("SELECT nombre, apellido, email FROM clientes;"), use_container_width=True)
    with tab_abogados:
        # Similar al de clientes
        pass

# --- Aplicación Principal ---
def main():
    st.sidebar.title("Menú de Navegación")
    opciones = {
        "Dashboard": "📊", "Crear Nuevo Caso": "📝", 
        "Gestión Documental": "📂", "Gestionar Clientes y Abogados": "👥"
    }
    seleccion = st.sidebar.radio("Módulos", list(opciones.keys()), format_func=lambda x: f"{opciones[x]} {x}", label_visibility="collapsed")
    
    st.title("⚖️ LegalIA - Sistema de Gestión de Casos")

    if seleccion == "Dashboard": mostrar_dashboard()
    elif seleccion == "Crear Nuevo Caso": mostrar_crear_caso()
    elif seleccion == "Gestionar Clientes y Abogados": mostrar_gestion_entidades()
    elif seleccion == "Gestión Documental": mostrar_gestion_documental()

if __name__ == "__main__":
    main()

