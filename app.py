import streamlit as st
import psycopg2
import pandas as pd
import os
import google.generativeai as genai
from psycopg2 import sql

# --- CONFIGURACIÓN DE LA PÁGINA ---
st.set_page_config(
    page_title="LegalIA - Sistema de Gestión",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ESTILOS CSS PERSONALIZADOS ---
st.markdown("""
<style>
    .reportview-container {
        background: #f0f2f6;
    }
    .sidebar .sidebar-content {
        background: #ffffff;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 8px;
        border: none;
        padding: 10px 24px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        cursor: pointer;
        transition-duration: 0.4s;
    }
    .stButton>button:hover {
        background-color: white;
        color: black;
        border: 2px solid #4CAF50;
    }
    .stTextInput>div>div>input {
        border-radius: 8px;
    }
    .stTextArea>div>div>textarea {
        border-radius: 8px;
    }
    .stSelectbox>div>div {
        border-radius: 8px;
    }
    .css-1d391kg {
        border-radius: 12px;
        padding: 2rem;
        background-color: #ffffff;
        box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
    }
    h1, h2, h3 {
        color: #0a2f5a;
    }
</style>
""", unsafe_allow_html=True)


# --- CONFIGURACIÓN DE SECRETOS Y CONEXIONES ---

# Para ejecutar en Google Colab, crea un archivo secrets.toml y súbelo.
# Formato de secrets.toml:
# [database]
# host = "db.xxxxxxxx.supabase.co"
# port = 5432
# dbname = "postgres"
# user = "postgres"
# password = "tu-super-password"
#
# [ai]
# google_api_key = "tu-api-key-de-gemini"

def init_connection():
    """Inicializa la conexión a la base de datos PostgreSQL."""
    try:
        conn = psycopg2.connect(**st.secrets["database"])
        return conn
    except Exception as e:
        st.error(f"Error al conectar a la base de datos: {e}")
        return None

def configure_ai():
    """Configura la API de IA de Google."""
    try:
        genai.configure(api_key=st.secrets["ai"]["google_api_key"])
    except Exception as e:
        st.error(f"Error al configurar la API de IA. Asegúrate de que tu API Key es correcta. Error: {e}")
        
# --- FUNCIONES DE LA BASE DE DATOS ---

def run_query(query, params=None):
    """Ejecuta una consulta SELECT y devuelve los resultados como un DataFrame."""
    conn = init_connection()
    if conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if cur.description:
                return pd.DataFrame(cur.fetchall(), columns=[desc[0] for desc in cur.description])
    return pd.DataFrame()

def call_proc(proc_name, params=None):
    """Llama a un procedimiento almacenado."""
    conn = init_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.callproc(proc_name, params)
                conn.commit()
            st.success("Operación realizada con éxito.")
        except Exception as e:
            st.error(f"Error al ejecutar el procedimiento: {e}")
        finally:
            conn.close()

def call_func(func_name, params=None):
    """Llama a una función que devuelve un valor (ej: el ID de una nueva fila)."""
    conn = init_connection()
    result = None
    if conn:
        try:
            with conn.cursor() as cur:
                if params:
                    placeholders = ', '.join(['%s'] * len(params))
                    cur.execute(f"SELECT * FROM {func_name}({placeholders});", params)
                else:
                    cur.execute(f"SELECT * FROM {func_name}();")
                
                result = cur.fetchall()
            conn.commit()
            st.success("Función ejecutada con éxito.")
        except Exception as e:
            st.error(f"Error al ejecutar la función: {e}")
        finally:
            conn.close()
    return result

# --- FUNCIONES DE IA ---

def generar_resumen_ia(descripcion_caso):
    """Genera un resumen de un caso usando el modelo de IA de Google."""
    if 'ai' not in st.secrets or 'google_api_key' not in st.secrets['ai']:
        st.warning("La clave API de IA no está configurada en los secretos.")
        return "Error: API Key no configurada."

    configure_ai()
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"""
        Actúa como un asistente legal experto. Analiza la siguiente descripción de un caso legal y genera un resumen conciso en español.
        El resumen debe incluir:
        1.  **Tipo de Caso:** (ej. Penal, Civil, Mercantil).
        2.  **Partes Involucradas:** (si se mencionan).
        3.  **Objetivo Principal:** (qué se busca con el caso).
        4.  **Puntos Clave:** (2 o 3 puntos cruciales).

        **Descripción del Caso:**
        "{descripcion_caso}"

        **Resumen:**
        """
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        st.error(f"Ocurrió un error al generar el resumen con IA: {e}")
        return "No se pudo generar el resumen."

def busqueda_inteligente_ia(query_usuario, df_casos):
    """Usa IA para encontrar casos relevantes basados en una búsqueda en lenguaje natural."""
    if 'ai' not in st.secrets or 'google_api_key' not in st.secrets['ai']:
        st.warning("La clave API de IA no está configurada en los secretos.")
        return []

    configure_ai()
    try:
        model = genai.GenerativeModel('gemini-pro')
        
        # Preparamos los datos de los casos para el prompt
        casos_texto = ""
        for index, row in df_casos.iterrows():
            casos_texto += f"ID: {row['caso_id']}, Título: {row['titulo_caso']}, Descripción: {row['descripcion_caso']}, Cliente: {row['nombre_cliente']}, Abogado: {row['nombre_abogado']}\n"

        prompt = f"""
        Eres un motor de búsqueda legal. Un usuario ha realizado la siguiente consulta: "{query_usuario}".
        Analiza la lista de casos proporcionada a continuación y devuelve únicamente los IDs de los casos que son más relevantes para la consulta del usuario.
        Devuelve los IDs como una lista de números separados por comas. Si ningún caso es relevante, devuelve una lista vacía.

        **Lista de Casos:**
        {casos_texto}

        **IDs Relevantes (separados por comas):**
        """
        
        response = model.generate_content(prompt)
        # Limpiamos y procesamos la respuesta para obtener solo los IDs
        ids_str = response.text.strip().split(',')
        ids_relevantes = [int(id_str.strip()) for id_str in ids_str if id_str.strip().isdigit()]
        return ids_relevantes

    except Exception as e:
        st.error(f"Ocurrió un error en la búsqueda inteligente: {e}")
        return []

# --- INTERFAZ DE USUARIO ---

st.title("⚖️ LegalIA - Sistema de Gestión de Casos")
st.markdown("Bienvenido al panel de control para la gestión de casos legales. Utilice el menú de la izquierda para navegar.")

# --- BARRA LATERAL ---
st.sidebar.header("Menú de Navegación")
opcion = st.sidebar.radio("Seleccione un Módulo", ["Dashboard", "Crear Nuevo Caso", "Gestionar Clientes y Abogados"])

# Cargar datos para el selector
clientes_df = run_query("SELECT id, nombre || ' ' || apellido as nombre_completo FROM clientes ORDER BY nombre_completo;")
abogados_df = run_query("SELECT id, nombre || ' ' || apellido as nombre_completo FROM abogados ORDER BY nombre_completo;")


if opcion == "Dashboard":
    st.header("📊 Dashboard de Casos")
    
    # Obtener todos los casos
    casos_df = call_func("obtener_casos_detallados")
    if isinstance(casos_df, list) and casos_df:
        casos_df = pd.DataFrame(casos_df, columns=['caso_id', 'titulo_caso', 'estado_caso', 'nombre_cliente', 'nombre_abogado', 'descripcion_caso', 'fecha_apertura_caso'])
    elif not isinstance(casos_df, pd.DataFrame):
        casos_df = pd.DataFrame()


    if not casos_df.empty:
        # --- Búsqueda Inteligente ---
        st.subheader("🔍 Búsqueda Inteligente")
        search_query = st.text_input("Busque casos por descripción, cliente, tipo, etc. (Ej: 'casos de divorcio de María')")

        if search_query:
            with st.spinner("Buscando con IA..."):
                ids_relevantes = busqueda_inteligente_ia(search_query, casos_df)
                if ids_relevantes:
                    st.success(f"Se encontraron {len(ids_relevantes)} casos relevantes.")
                    resultados_df = casos_df[casos_df['caso_id'].isin(ids_relevantes)]
                    st.dataframe(resultados_df)
                else:
                    st.warning("No se encontraron casos que coincidan con su búsqueda.")
        
        st.markdown("---")
        st.subheader("Todos los Casos")

        for index, row in casos_df.iterrows():
            with st.expander(f"**{row['titulo_caso']}** (Cliente: {row['nombre_cliente']} - Estado: {row['estado_caso']})"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(f"**Abogado Asignado:** {row['nombre_abogado']}")
                    st.markdown(f"**Fecha de Apertura:** {row['fecha_apertura_caso']}")
                    st.markdown(f"**Descripción:**")
                    st.info(row['descripcion_caso'])
                
                with col2:
                    st.markdown("**Acciones**")
                    # Actualizar estado
                    nuevo_estado = st.selectbox(
                        "Cambiar Estado",
                        ['Abierto', 'En Progreso', 'Cerrado', 'Suspendido'],
                        index=['Abierto', 'En Progreso', 'Cerrado', 'Suspendido'].index(row['estado_caso']),
                        key=f"estado_{row['caso_id']}"
                    )
                    if st.button("Actualizar Estado", key=f"update_{row['caso_id']}"):
                        call_proc("actualizar_estado_caso", (row['caso_id'], nuevo_estado))
                        st.experimental_rerun()
                    
                    # Resumen con IA
                    if st.button("Generar Resumen con IA", key=f"ia_{row['caso_id']}"):
                        with st.spinner("La IA está analizando el caso..."):
                            resumen = generar_resumen_ia(row['descripcion_caso'])
                            st.subheader("Resumen Generado por IA")
                            st.markdown(resumen)
    else:
        st.warning("No hay casos registrados en el sistema.")


elif opcion == "Crear Nuevo Caso":
    st.header("✍️ Registrar Nuevo Caso")
    with st.form("nuevo_caso_form", clear_on_submit=True):
        titulo = st.text_input("Título del Caso", help="Ej: Demanda por incumplimiento de contrato")
        descripcion = st.text_area("Descripción Detallada del Caso", height=200)
        
        # Selectores para cliente y abogado
        cliente_map = dict(zip(clientes_df['nombre_completo'], clientes_df['id']))
        abogado_map = dict(zip(abogados_df['nombre_completo'], abogados_df['id']))

        cliente_seleccionado = st.selectbox("Seleccione el Cliente", options=clientes_df['nombre_completo'])
        abogado_seleccionado = st.selectbox("Asignar al Abogado", options=abogados_df['nombre_completo'])
        
        submitted = st.form_submit_button("Guardar Caso")
        if submitted:
            if not titulo or not descripcion or not cliente_seleccionado or not abogado_seleccionado:
                st.error("Por favor, complete todos los campos.")
            else:
                cliente_id = cliente_map[cliente_seleccionado]
                abogado_id = abogado_map[abogado_seleccionado]
                call_func("crear_caso", (titulo, descripcion, cliente_id, abogado_id))
                st.balloons()

elif opcion == "Gestionar Clientes y Abogados":
    st.header("👥 Gestión de Clientes y Abogados")
    
    tab1, tab2 = st.tabs(["Clientes", "Abogados"])

    with tab1:
        st.subheader("Lista de Clientes")
        st.dataframe(clientes_df)
        with st.expander("Añadir Nuevo Cliente"):
             with st.form("nuevo_cliente_form", clear_on_submit=True):
                nombre = st.text_input("Nombre del Cliente")
                apellido = st.text_input("Apellido del Cliente")
                email = st.text_input("Email")
                telefono = st.text_input("Teléfono")
                submitted = st.form_submit_button("Guardar Cliente")
                if submitted:
                    conn = init_connection()
                    if conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "INSERT INTO clientes (nombre, apellido, email, telefono) VALUES (%s, %s, %s, %s)",
                                (nombre, apellido, email, telefono)
                            )
                            conn.commit()
                        st.success("Cliente añadido.")
                        st.experimental_rerun()
    
    with tab2:
        st.subheader("Lista de Abogados")
        st.dataframe(abogados_df)
        with st.expander("Añadir Nuevo Abogado"):
             with st.form("nuevo_abogado_form", clear_on_submit=True):
                nombre = st.text_input("Nombre del Abogado")
                apellido = st.text_input("Apellido del Abogado")
                especialidad = st.text_input("Especialidad")
                email = st.text_input("Email del Abogado")
                submitted = st.form_submit_button("Guardar Abogado")
                if submitted:
                    conn = init_connection()
                    if conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "INSERT INTO abogados (nombre, apellido, especialidad, email) VALUES (%s, %s, %s, %s)",
                                (nombre, apellido, especialidad, email)
                            )
                            conn.commit()
                        st.success("Abogado añadido.")
                        st.experimental_rerun()

st.sidebar.info(
    """
    **LegalIA v1.0**
    
    Un sistema inteligente para la gestión legal.
    - **Dashboard:** Visualiza y busca casos.
    - **Crear Caso:** Registra nuevos expedientes.
    - **Gestionar:** Administra clientes y abogados.
    """
)   