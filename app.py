import streamlit as st
import psycopg2
import pandas as pd
import google.generativeai as genai
from supabase import create_client, Client
import io

# --- Configuración de la Página ---
st.set_page_config(
    page_title="LegalIA - Gestión de Casos",
    page_icon="⚖️",
    layout="wide"
)

# --- Conexión a Base de Datos (Función Cacheada) ---
@st.cache_resource(ttl=3600)
def init_db_connection():
    try:
        connection = psycopg2.connect(
            host=st.secrets["database"]["host"],
            port=st.secrets["database"]["port"],
            dbname=st.secrets["database"]["dbname"],
            user=st.secrets["database"]["user"],
            password=st.secrets["database"]["password"]
        )
        return connection
    except Exception as e:
        st.error(f"Error al conectar a la base de datos: {e}")
        return None

# --- Conexión a Supabase Storage (Función Cacheada) ---
@st.cache_resource
def init_supabase_client():
    try:
        url = st.secrets["supabase"]["url"]
        key = st.secrets["supabase"]["key"]
        return create_client(url, key)
    except Exception as e:
        st.error(f"Error al conectar con Supabase: {e}")
        return None

# --- Configuración del Modelo de IA de Google ---
try:
    genai.configure(api_key=st.secrets["ai"]["google_api_key"])
    model = genai.GenerativeModel('gemini-1.5-flash')
except Exception as e:
    st.warning(f"No se pudo configurar el modelo de IA. La clave de API podría faltar o ser inválida. Error: {e}")
    model = None

# --- Funciones de Lógica de Negocio (Backend) ---

def run_procedure(proc_name, params=None):
    """Ejecuta un procedimiento almacenado."""
    conn = init_db_connection()
    if conn is None: return
    try:
        with conn.cursor() as cur:
            cur.callproc(proc_name, params)
            conn.commit()
    except Exception as e:
        conn.rollback()
        st.error(f"Error al ejecutar el procedimiento: {e}")

def run_query(query, params=None):
    """Ejecuta una consulta SQL y devuelve los resultados como DataFrame."""
    conn = init_db_connection()
    if conn is None: return pd.DataFrame()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if cur.description:
                columns = [desc[0] for desc in cur.description]
                return pd.DataFrame(cur.fetchall(), columns=columns)
            else:
                return pd.DataFrame()
    except Exception as e:
        # En caso de un error de transacción abortada, intentar refrescar la conexión
        if "current transaction is aborted" in str(e):
            st.cache_resource.clear() # Limpiar el cache para forzar una nueva conexión
            conn = init_db_connection()
        st.error(f"Error al ejecutar la función: {e}")
        return pd.DataFrame()

def get_clients():
    return run_query("SELECT id_cliente, nombre || ' ' || apellido as nombre_completo FROM clientes ORDER BY nombre;")

def get_lawyers():
    return run_query("SELECT id_abogado, nombre || ' ' || apellido as nombre_completo FROM abogados ORDER BY nombre;")

def get_cases_detailed():
    return run_query("SELECT * FROM obtener_casos_detallados();")

def get_documents_for_case(case_id):
    return run_query("SELECT id_documento, nombre_archivo, descripcion, fecha_subida, ruta_storage FROM documentos WHERE id_caso = %s ORDER BY fecha_subida DESC;", (case_id,))

# --- Interfaz de Usuario (Frontend) ---

st.sidebar.title("Menú de Navegación")
st.sidebar.markdown("Seleccione un Módulo")
page = st.sidebar.radio("Módulos", ["Dashboard", "Crear Nuevo Caso", "Gestión Documental", "Gestionar Clientes y Abogados"], label_visibility="hidden")

st.sidebar.markdown("---")
st.sidebar.info(
    """
    **LegalIA v1.0**

    Un sistema inteligente para la gestión legal.
    - **Dashboard:** Visualiza y busca casos.
    - **Crear Caso:** Registra nuevos expedientes.
    - **Gestionar:** Administra clientes y abogados.
    """
)

# --- Título Principal ---
st.markdown("<h1 style='text-align: center; color: #4A4A4A;'>⚖️ LegalIA - Sistema de Gestión de Casos</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Bienvenido al panel de control para la gestión de casos legales. Utilice el menú de la izquierda para navegar.</p>", unsafe_allow_html=True)
st.markdown("---")


# --- Página del Dashboard ---
if page == "Dashboard":
    st.header("📊 Dashboard de Casos")
    cases = get_cases_detailed()

    if cases.empty:
        st.info("No hay casos registrados en el sistema.")
    else:
        for index, case in cases.iterrows():
            with st.expander(f"**{case['titulo']}** (Cliente: {case['cliente']}) - Estado: {case['estado']}"):
                col1, col2 = st.columns([3, 2])
                with col1:
                    st.markdown(f"**Abogado Asignado:** {case['abogado']}")
                    st.markdown(f"**Fecha de Apertura:** {case['fecha_apertura'].strftime('%d/%m/%Y')}")
                    st.markdown(f"**Descripción:**\n{case['descripcion']}")

                    # Módulo de IA para Resumen
                    if model and st.button("Generar Resumen con IA", key=f"sum_{case['id_caso']}"):
                        with st.spinner("La IA está analizando el caso..."):
                            try:
                                response = model.generate_content(
                                    f"Resume el siguiente caso legal en 2 o 3 puntos clave, como si fueras un abogado senior revisándolo: Título: {case['titulo']}. Descripción: {case['descripcion']}."
                                )
                                st.success("**Resumen por IA:**")
                                st.markdown(response.text)
                            except Exception as e:
                                st.error(f"No se pudo generar el resumen: {e}")

                with col2:
                    st.subheader("Estado del Caso")
                    new_status = st.selectbox(
                        "Cambiar estado",
                        ["Abierto", "En Progreso", "Cerrado", "Archivado"],
                        index=["Abierto", "En Progreso", "Cerrado", "Archivado"].index(case['estado']),
                        key=f"status_{case['id_caso']}"
                    )
                    if st.button("Actualizar Estado", key=f"upd_{case['id_caso']}"):
                        run_procedure("actualizar_estado_caso", (case['id_caso'], new_status))
                        st.toast("Estado actualizado.")
                        st.rerun()
                
                # Sección de Documentos
                st.markdown("---")
                st.subheader("Documentos del Caso")
                documents = get_documents_for_case(case['id_caso'])
                if documents.empty:
                    st.write("No hay documentos asociados a este caso.")
                else:
                    supabase_client = init_supabase_client()
                    for idx, doc in documents.iterrows():
                        doc_col1, doc_col2 = st.columns([4, 1])
                        with doc_col1:
                            st.write(f"📄 **{doc['nombre_archivo']}** - Subido: {doc['fecha_subida'].strftime('%d/%m/%Y %H:%M')}")
                        with doc_col2:
                            if supabase_client:
                                try:
                                    signed_url = supabase_client.storage.from_("documentos_casos").create_signed_url(doc['ruta_storage'], 60)
                                    st.link_button("Descargar", signed_url['signedURL'])
                                except Exception as e:
                                    st.error("No se pudo generar el enlace.")


# --- Página de Creación de Casos ---
elif page == "Crear Nuevo Caso":
    st.header("➕ Crear Nuevo Caso")
    
    clients = get_clients()
    lawyers = get_lawyers()

    with st.form("new_case_form"):
        case_title = st.text_input("Título del Caso")
        case_description = st.text_area("Descripción Detallada")

        selected_client_name = None
        client_map = {}
        if not clients.empty:
            client_map = dict(zip(clients['nombre_completo'], clients['id_cliente']))
            selected_client_name = st.selectbox("Seleccionar Cliente", client_map.keys())
        else:
            st.warning("No hay clientes registrados. Por favor, registre un cliente primero.")

        selected_lawyer_name = None
        lawyer_map = {}
        if not lawyers.empty:
            lawyer_map = dict(zip(lawyers['nombre_completo'], lawyers['id_abogado']))
            selected_lawyer_name = st.selectbox("Asignar Abogado", lawyer_map.keys())
        else:
            st.warning("No hay abogados registrados. Por favor, registre un abogado primero.")

        submitted = st.form_submit_button("Guardar Caso")
        if submitted:
            if not all([case_title, case_description, selected_client_name, selected_lawyer_name]):
                st.error("Todos los campos son obligatorios.")
            else:
                client_id = client_map[selected_client_name]
                lawyer_id = lawyer_map[selected_lawyer_name]
                run_procedure("crear_caso", (case_title, case_description, client_id, lawyer_id))
                st.success("¡Caso creado exitosamente!")


# --- Página de Gestión Documental ---
elif page == "Gestión Documental":
    st.header("📂 Gestión Documental")

    cases = get_cases_detailed()
    if cases.empty:
        st.warning("No hay casos registrados. Por favor, cree un caso antes de subir documentos.")
    else:
        case_map = dict(zip(cases['titulo'], cases['id_caso']))
        selected_case_title = st.selectbox("Seleccione el Caso al que pertenece el documento", case_map.keys())
        
        uploaded_file = st.file_uploader("Subir nuevo documento", type=['pdf', 'docx', 'jpg', 'png', 'txt'])
        doc_description = st.text_area("Descripción del documento")

        if st.button("Guardar Documento"):
            if uploaded_file is not None and selected_case_title:
                case_id = case_map[selected_case_title]
                file_bytes = uploaded_file.getvalue()
                file_name = uploaded_file.name
                
                storage_path = f"{case_id}/{file_name}"

                supabase_client = init_supabase_client()
                if supabase_client:
                    try:
                        with st.spinner(f"Subiendo '{file_name}'..."):
                            supabase_client.storage.from_("documentos_casos").upload(file=file_bytes, path=storage_path, file_options={"content-type": uploaded_file.type})
                            run_procedure("crear_documento", (file_name, doc_description, case_id, storage_path))
                        st.success(f"¡Documento '{file_name}' subido y asociado al caso '{selected_case_title}'!")
                    except Exception as e:
                        if "duplicate" in str(e):
                             st.warning(f"Un archivo con el nombre '{file_name}' ya existe en este caso. Por favor, cambie el nombre del archivo si desea subirlo de nuevo.")
                        else:
                            st.error(f"Error al subir el archivo: {e}")
                else:
                    st.error("El cliente de almacenamiento no está inicializado.")

            else:
                st.error("Por favor, seleccione un caso y un archivo para subir.")


# --- Página de Gestión de Clientes y Abogados ---
elif page == "Gestionar Clientes y Abogados":
    st.header("👥 Gestión de Clientes y Abogados")

    tab1, tab2 = st.tabs(["Clientes", "Abogados"])

    with tab1:
        st.subheader("Registrar Nuevo Cliente")
        with st.form("new_client_form"):
            nombre_cli = st.text_input("Nombre")
            apellido_cli = st.text_input("Apellido")
            email_cli = st.text_input("Email")
            telefono_cli = st.text_input("Teléfono")
            direccion_cli = st.text_input("Dirección")
            submitted_cli = st.form_submit_button("Guardar Cliente")

            if submitted_cli:
                if not all([nombre_cli, apellido_cli, email_cli, telefono_cli, direccion_cli]):
                    st.error("Todos los campos son obligatorios.")
                else:
                    run_procedure("crear_cliente", (nombre_cli, apellido_cli, email_cli, telefono_cli, direccion_cli))
                    st.success("¡Cliente guardado con éxito!")
                    st.rerun()
        
        st.markdown("---")
        st.subheader("Lista de Clientes")
        clientes_df = run_query("SELECT nombre, apellido, email, telefono, direccion FROM clientes ORDER BY nombre, apellido;")
        st.dataframe(clientes_df, use_container_width=True)

    with tab2:
        st.subheader("Registrar Nuevo Abogado")
        with st.form("new_lawyer_form"):
            nombre_abo = st.text_input("Nombre", key="abo_n")
            apellido_abo = st.text_input("Apellido", key="abo_a")
            especialidad_abo = st.text_input("Especialidad", key="abo_e")
            email_abo = st.text_input("Email", key="abo_em")
            telefono_abo = st.text_input("Teléfono", key="abo_t")
            submitted_abo = st.form_submit_button("Guardar Abogado")

            if submitted_abo:
                if not all([nombre_abo, apellido_abo, especialidad_abo, email_abo, telefono_abo]):
                    st.error("Todos los campos son obligatorios.")
                else:
                    run_procedure("crear_abogado", (nombre_abo, apellido_abo, especialidad_abo, email_abo, telefono_abo))
                    st.success("¡Abogado guardado con éxito!")
                    st.rerun()

        st.markdown("---")
        st.subheader("Lista de Abogados")
        abogados_df = run_query("SELECT nombre, apellido, especialidad, email, telefono FROM abogados ORDER BY nombre, apellido;")
        st.dataframe(abogados_df, use_container_width=True)

