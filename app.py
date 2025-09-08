import streamlit as st
import pandas as pd
import psycopg2
from psycopg2 import sql
import google.generativeai as genai
from supabase import create_client, Client
import io
import time

# --- Configuración de la Página ---
st.set_page_config(
    page_title="LegalIA - Sistema de Gestión",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Conexión a Supabase Storage ---
try:
    SUPABASE_URL = st.secrets["supabase"]["url"]
    SUPABASE_KEY = st.secrets["supabase"]["key"]
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    st.error(f"Error al inicializar Supabase. Verifica los secrets. {e}")
    supabase = None

# --- Conexión a la Base de Datos ---
@st.cache_resource
def init_connection():
    try:
        conn = psycopg2.connect(**st.secrets["database"])
        return conn
    except Exception as e:
        st.error(f"Error al conectar con la base de datos: {e}")
        return None

conn = init_connection()

# --- Funciones de la Base de Datos ---
def run_query(query, params=None):
    if conn is None:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if cur.description:
                return cur.fetchall()
    except Exception as e:
        st.error(f"Error al ejecutar la consulta: {e}")
        conn.rollback()
        return None

def call_proc(proc_name, params=None):
    if conn is None:
        return False
    try:
        with conn.cursor() as cur:
            cur.callproc(proc_name, params)
            conn.commit()
            return True
    except Exception as e:
        st.error(f"Error al ejecutar el procedimiento: {e}")
        conn.rollback()
        return False

# --- Configuración del Modelo de IA de Google ---
try:
    GEMINI_API_KEY = st.secrets["ai"]["google_api_key"]
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-pro')
except Exception as e:
    st.warning(f"No se pudo configurar el modelo de IA. Verifica la API Key. {e}")
    model = None

# --- Interfaz de Usuario (UI) ---

# --- BARRA LATERAL ---
with st.sidebar:
    st.title("⚖️ LegalIA - Sistema de Gestión")
    st.markdown("---")
    st.header("Menú de Navegación")
    page = st.radio("Seleccione un Módulo", [
        "Dashboard",
        "Crear Nuevo Caso",
        "Gestión Documental",
        "Gestionar Clientes y Abogados"
    ])
    st.markdown("---")
    st.info(
        """
        **LegalIA v1.0**
        Un sistema inteligente para la gestión legal.
        - **Dashboard:** Visualiza y busca casos.
        - **Crear Caso:** Registra nuevos expedientes.
        - **Gestionar:** Administra clientes, abogados y documentos.
        """
    )

# --- MÓDULOS DE LA APLICACIÓN ---

# --- Dashboard de Casos ---
def dashboard():
    st.header("📊 Dashboard de Casos")
    
    # Obtener casos
    casos_data = run_query("SELECT * FROM obtener_casos_detallados();")
    
    if not casos_data:
        st.warning("No hay casos registrados en el sistema.")
        return

    df_casos = pd.DataFrame(casos_data, columns=['ID', 'Título', 'Cliente', 'Abogado', 'Descripción', 'Estado', 'Fecha Apertura'])
    
    # Filtros
    col1, col2 = st.columns(2)
    with col1:
        filtro_estado = st.multiselect("Filtrar por Estado", options=df_casos["Estado"].unique(), default=df_casos["Estado"].unique())
    with col2:
        filtro_texto = st.text_input("Buscar por Título o Descripción")

    df_filtrado = df_casos[df_casos["Estado"].isin(filtro_estado)]
    if filtro_texto:
        df_filtrado = df_filtrado[
            df_filtrado["Título"].str.contains(filtro_texto, case=False) |
            df_filtrado["Descripción"].str.contains(filtro_texto, case=False)
        ]

    if df_filtrado.empty:
        st.info("No se encontraron casos que coincidan con los filtros.")
        return

    # Mostrar casos
    for index, row in df_filtrado.iterrows():
        with st.expander(f"Caso #{row['ID']}: {row['Título']} ({row['Estado']})"):
            col1, col2, col3 = st.columns(3)
            col1.metric("Cliente", row['Cliente'])
            col2.metric("Abogado Asignado", row['Abogado'])
            col3.metric("Fecha de Apertura", str(row['Fecha Apertura'].date()))
            
            st.markdown("**Descripción del Caso:**")
            st.write(row['Descripción'])
            
            # Sección de documentos del caso
            st.markdown("**Documentos Asociados:**")
            documentos_data = run_query("SELECT id_documento, nombre_archivo, fecha_subida FROM documentos WHERE id_caso = %s", (row['ID'],))
            if documentos_data:
                for doc in documentos_data:
                    doc_id, doc_nombre, doc_fecha = doc
                    try:
                        # Crear un enlace de descarga firmado que expira en 60 segundos
                        signed_url = supabase.storage.from_("documentos_casos").create_signed_url(f"{row['ID']}/{doc_nombre}", 60)
                        st.markdown(f"📄 [{doc_nombre}]({signed_url['signedURL']}) - Subido el {doc_fecha.date()}")
                    except Exception as e:
                        st.error(f"No se pudo generar el enlace para {doc_nombre}. Error: {e}")
            else:
                st.info("No hay documentos para este caso.")
            
            # Actualizar estado
            with st.form(key=f"form_update_{row['ID']}"):
                nuevo_estado = st.selectbox(
                    "Cambiar Estado",
                    options=['Abierto', 'En Progreso', 'Cerrado', 'Archivado'],
                    index=['Abierto', 'En Progreso', 'Cerrado', 'Archivado'].index(row['Estado']),
                    key=f"select_{row['ID']}"
                )
                if st.form_submit_button("Actualizar Estado"):
                    if call_proc("actualizar_estado_caso", (row['ID'], nuevo_estado)):
                        st.success("¡Estado del caso actualizado con éxito!")
                        st.rerun()
                    else:
                        st.error("No se pudo actualizar el estado del caso.")

# --- Crear Nuevo Caso ---
def crear_nuevo_caso():
    st.header("📝 Crear Nuevo Caso")
    
    clientes = run_query("SELECT id_cliente, nombre || ' ' || apellido FROM clientes ORDER BY nombre;")
    abogados = run_query("SELECT id_abogado, nombre || ' ' || apellido FROM abogados ORDER BY nombre;")

    if not clientes:
        st.error("No se pueden crear casos. Por favor, registre al menos un cliente primero.")
        return
    if not abogados:
        st.error("No se pueden crear casos. Por favor, registre al menos un abogado primero.")
        return

    clientes_dict = {nombre: id_cliente for id_cliente, nombre in clientes}
    abogados_dict = {nombre: id_abogado for id_abogado, nombre in abogados}

    with st.form("nuevo_caso_form"):
        titulo = st.text_input("Título del Caso", max_chars=100)
        descripcion = st.text_area("Descripción Detallada del Caso")
        cliente_nombre = st.selectbox("Seleccionar Cliente", options=clientes_dict.keys())
        abogado_nombre = st.selectbox("Asignar Abogado", options=abogados_dict.keys())
        
        submitted = st.form_submit_button("Guardar Caso")
        if submitted:
            if not all([titulo, descripcion, cliente_nombre, abogado_nombre]):
                st.warning("Por favor, complete todos los campos.")
            else:
                id_cliente = clientes_dict[cliente_nombre]
                id_abogado = abogados_dict[abogado_nombre]
                if call_proc("crear_caso", (titulo, descripcion, id_cliente, id_abogado)):
                    st.success("¡Nuevo caso creado con éxito!")
                else:
                    st.error("Hubo un error al crear el caso.")

# --- Gestión de Clientes y Abogados ---
def gestion_clientes_abogados():
    st.header("👥 Gestión de Clientes y Abogados")
    
    tab1, tab2 = st.tabs(["Clientes", "Abogados"])

    with tab1:
        st.subheader("Registrar Nuevo Cliente")
        with st.form("nuevo_cliente_form", clear_on_submit=True):
            nombre = st.text_input("Nombre", key="cliente_nombre")
            apellido = st.text_input("Apellido", key="cliente_apellido")
            email = st.text_input("Email", key="cliente_email")
            telefono = st.text_input("Teléfono", key="cliente_telefono")
            direccion = st.text_input("Dirección", key="cliente_direccion")
            
            submitted = st.form_submit_button("Guardar Cliente")
            if submitted:
                if call_proc("crear_cliente", (nombre, apellido, email, telefono, direccion)):
                    st.success("¡Cliente guardado con éxito!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Error al guardar el cliente.")
        
        st.markdown("---")
        st.subheader("Lista de Clientes")
        clientes_data = run_query("SELECT nombre, apellido, email, telefono, direccion FROM clientes ORDER BY nombre, apellido;")
        if clientes_data:
            df_clientes = pd.DataFrame(clientes_data, columns=["Nombre", "Apellido", "Email", "Teléfono", "Dirección"])
            st.dataframe(df_clientes, use_container_width=True)
        else:
            st.info("No hay clientes registrados.")

    with tab2:
        st.subheader("Registrar Nuevo Abogado")
        with st.form("nuevo_abogado_form", clear_on_submit=True):
            nombre_abogado = st.text_input("Nombre", key="abogado_nombre")
            apellido_abogado = st.text_input("Apellido", key="abogado_apellido")
            especialidad = st.text_input("Especialidad", key="abogado_especialidad")
            email_abogado = st.text_input("Email", key="abogado_email")
            telefono_abogado = st.text_input("Teléfono", key="abogado_telefono")

            submitted_abogado = st.form_submit_button("Guardar Abogado")
            if submitted_abogado:
                if call_proc("crear_abogado", (nombre_abogado, apellido_abogado, especialidad, email_abogado, telefono_abogado)):
                    st.success("¡Abogado guardado con éxito!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Error al guardar el abogado.")

        st.markdown("---")
        st.subheader("Lista de Abogados")
        abogados_data = run_query("SELECT nombre, apellido, especialidad, email, telefono FROM abogados ORDER BY nombre, apellido;")
        if abogados_data:
            df_abogados = pd.DataFrame(abogados_data, columns=["Nombre", "Apellido", "Especialidad", "Email", "Teléfono"])
            st.dataframe(df_abogados, use_container_width=True)
        else:
            st.info("No hay abogados registrados.")

# --- Gestión Documental ---
def gestion_documental():
    st.header("📂 Gestión Documental")

    casos = run_query("SELECT id_caso, titulo FROM casos WHERE estado != 'Cerrado' AND estado != 'Archivado' ORDER BY id_caso DESC;")
    if not casos:
        st.warning("No hay casos activos para asociar documentos. Por favor, cree un caso primero.")
        return

    casos_dict = {titulo: id_caso for id_caso, titulo in casos}
    
    st.subheader("Subir Nuevo Documento a un Caso")
    
    caso_seleccionado = st.selectbox("Seleccione el Caso", options=casos_dict.keys())
    uploaded_file = st.file_uploader("Elija un archivo (PDF, DOCX, JPG, etc.)", type=None)

    if st.button("Subir y Asociar Documento"):
        if uploaded_file is not None and caso_seleccionado and supabase:
            id_caso = casos_dict[caso_seleccionado]
            file_contents = uploaded_file.read()
            file_name = uploaded_file.name
            
            # Crear un objeto de archivo en memoria para la librería de Supabase
            file_obj = io.BytesIO(file_contents)
            file_obj.name = file_name
            
            try:
                # Subir archivo al bucket
                path_on_supastorage = f"{id_caso}/{file_name}"
                supabase.storage.from_("documentos_casos").upload(path_on_supastorage, file_obj)
                
                # Guardar registro en la base de datos
                if call_proc("crear_documento", (file_name, "Descripción pendiente", id_caso, path_on_supastorage)):
                    st.success(f"¡Archivo '{file_name}' subido y asociado al caso '{caso_seleccionado}' con éxito!")
                else:
                    st.error("El archivo se subió, pero hubo un error al registrarlo en la base de datos.")

            except Exception as e:
                # Manejar el error específico de archivo duplicado
                if "Duplicate" in str(e) or "already exists" in str(e):
                     st.warning(f"Ya existe un archivo con el nombre '{file_name}' en este caso. Por favor, cambie el nombre del archivo si desea subir una nueva versión.")
                else:
                    st.error(f"Error al subir el archivo a Supabase Storage: {e}")

        else:
            st.warning("Por favor, seleccione un caso y un archivo para subir.")

# --- Controlador Principal ---
if page == "Dashboard":
    dashboard()
elif page == "Crear Nuevo Caso":
    crear_nuevo_caso()
elif page == "Gestionar Clientes y Abogados":
    gestion_clientes_abogados()
elif page == "Gestión Documental":
    gestion_documental()

