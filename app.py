import streamlit as st
import pandas as pd
import psycopg2
import google.generativeai as genai
import time

# --- Configuración de la Página ---
st.set_page_config(
    page_title="LegalIA - Sistema de Gestión",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Funciones de Conexión a la Base de Datos ---

# Intenta obtener las credenciales de los secretos de Streamlit
try:
    DB_CONFIG = st.secrets["database"]
    AI_CONFIG = st.secrets["ai"]
    genai.configure(api_key=AI_CONFIG['google_api_key'])
    MODELO_IA = genai.GenerativeModel('gemini-1.5-flash')
except (FileNotFoundError, KeyError):
    st.error("⚠️ Error de Configuración: No se encontraron las credenciales de la base de datos o de la API de IA. Asegúrate de que tu archivo `secrets.toml` está configurado correctamente o los secretos están en Streamlit Cloud.")
    st.stop()


def get_db_connection():
    """Establece y devuelve una conexión a la base de datos PostgreSQL."""
    try:
        conn = psycopg2.connect(
            dbname=DB_CONFIG['dbname'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port']
        )
        return conn
    except Exception as e:
        st.error(f"Error al conectar a la base de datos: {e}")
        return None

def fetch_data(query, params=None):
    """Ejecuta una consulta SELECT y devuelve los resultados como un DataFrame de Pandas."""
    conn = get_db_connection()
    if conn:
        try:
            return pd.read_sql_query(query, conn, params=params)
        except Exception as e:
            st.error(f"Error al ejecutar la función: {e}")
            return pd.DataFrame()
        finally:
            conn.close()
    return pd.DataFrame()

def execute_procedure(procedure_call, params=None):
    """Ejecuta un procedimiento almacenado que no devuelve resultados (INSERT, UPDATE, DELETE)."""
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
        finally:
            conn.close()
    return False

# --- Funciones de IA ---

def resumir_caso_ia(descripcion):
    """Utiliza la IA de Gemini para generar un resumen conciso de la descripción de un caso."""
    if not descripcion or not isinstance(descripcion, str) or len(descripcion.strip()) < 10:
        return "Descripción demasiado breve para resumir."
    
    prompt = f"Actúa como un asistente legal experto. Resume el siguiente caso en un máximo de 3 frases clave, destacando el objetivo principal y las partes involucradas. Descripción: '{descripcion}'"
    
    try:
        with st.spinner("🧠 La IA está analizando el caso..."):
            response = MODELO_IA.generate_content(prompt)
            time.sleep(1) # Simula un pequeño retraso para mejorar la UX
        return response.text
    except Exception as e:
        st.warning(f"No se pudo generar el resumen con IA. Motivo: {e}")
        return "Resumen no disponible."

# --- Módulos de la Interfaz de Usuario (UI) ---

def mostrar_dashboard():
    """Muestra el panel principal con la lista de casos y opciones de búsqueda."""
    st.header("📊 Dashboard de Casos")
    
    casos_df = fetch_data("SELECT * FROM obtener_casos_detallados();")

    if casos_df.empty:
        st.info("No hay casos registrados en el sistema.")
        return

    # --- Filtros y Búsqueda ---
    col1, col2 = st.columns([2, 1])
    with col1:
        termino_busqueda = st.text_input("Buscar por título, descripción, cliente o abogado:", placeholder="Escribe para buscar...")
    with col2:
        estados_disponibles = ["Todos"] + list(casos_df['estado_caso'].unique())
        estado_seleccionado = st.selectbox("Filtrar por estado:", options=estados_disponibles)

    # Aplicar filtros
    casos_filtrados = casos_df
    if termino_busqueda:
        casos_filtrados = casos_filtrados[
            casos_filtrados.apply(
                lambda row: termino_busqueda.lower() in str(row['titulo_caso']).lower() or
                            termino_busqueda.lower() in str(row['descripcion_caso']).lower() or
                            termino_busqueda.lower() in str(row['cliente']).lower() or
                            termino_busqueda.lower() in str(row['abogado']).lower(),
                axis=1
            )
        ]
    if estado_seleccionado != "Todos":
        casos_filtrados = casos_filtrados[casos_filtrados['estado_caso'] == estado_seleccionado]

    st.write(f"Mostrando **{len(casos_filtrados)}** de **{len(casos_df)}** casos.")

    # --- Visualización de Casos ---
    if casos_filtrados.empty:
        st.warning("No se encontraron casos que coincidan con los criterios de búsqueda.")
    else:
        for index, caso in casos_filtrados.iterrows():
            with st.expander(f"**{caso['titulo_caso']}** - Cliente: {caso['cliente']} (Estado: {caso['estado_caso']})"):
                col_info, col_accion = st.columns([3, 1])
                with col_info:
                    st.markdown(f"**Abogado Asignado:** {caso['abogado']}")
                    st.markdown(f"**Fecha de Apertura:** {pd.to_datetime(caso['fecha_apertura_caso']).strftime('%d/%m/%Y %H:%M')}")
                    st.markdown("**Descripción:**")
                    st.caption(caso['descripcion_caso'])

                    if st.button("Generar Resumen con IA", key=f"ia_{caso['id_caso']}"):
                        resumen = resumir_caso_ia(caso['descripcion_caso'])
                        st.info(f"**Resumen IA:** {resumen}")
                
                with col_accion:
                    st.write("Cambiar Estado:")
                    nuevos_estados = ["Abierto", "En Progreso", "Cerrado", "En Espera"]
                    if caso['estado_caso'] in nuevos_estados:
                        nuevos_estados.remove(caso['estado_caso'])
                    
                    nuevo_estado = st.selectbox(
                        "Nuevo estado",
                        options=nuevos_estados,
                        key=f"estado_{caso['id_caso']}",
                        label_visibility="collapsed"
                    )
                    
                    if st.button("Actualizar Estado", key=f"actualizar_{caso['id_caso']}"):
                        if execute_procedure("CALL actualizar_estado_caso(%s, %s)", (caso['id_caso'], nuevo_estado)):
                            st.success(f"Estado del caso '{caso['titulo_caso']}' actualizado a '{nuevo_estado}'.")
                            st.rerun() # Recarga la página para ver el cambio
                        # El error se muestra en la función execute_procedure

def mostrar_crear_caso():
    """Muestra el formulario para registrar un nuevo caso."""
    st.header("📝 Crear Nuevo Caso")

    clientes_df = fetch_data("SELECT id, nombre, apellido FROM clientes ORDER BY nombre, apellido;")
    abogados_df = fetch_data("SELECT id, nombre, apellido FROM abogados ORDER BY nombre, apellido;")

    if clientes_df.empty or abogados_df.empty:
        st.warning("Debe registrar al menos un cliente y un abogado antes de poder crear un caso.")
        return

    clientes_map = {f"{row['nombre']} {row['apellido']}": row['id'] for index, row in clientes_df.iterrows()}
    abogados_map = {f"{row['nombre']} {row['apellido']}": row['id'] for index, row in abogados_df.iterrows()}

    with st.form("nuevo_caso_form"):
        titulo = st.text_input("Título del Caso", max_chars=255)
        descripcion = st.text_area("Descripción Detallada del Caso")
        
        col1, col2 = st.columns(2)
        with col1:
            cliente_seleccionado = st.selectbox("Seleccione un Cliente", options=clientes_map.keys())
        with col2:
            abogado_seleccionado = st.selectbox("Asignar a un Abogado", options=abogados_map.keys())
        
        submitted = st.form_submit_button("Registrar Caso")

        if submitted:
            if not titulo:
                st.error("El título del caso es obligatorio.")
            else:
                cliente_id = clientes_map[cliente_seleccionado]
                abogado_id = abogados_map[abogado_seleccionado]
                
                if execute_procedure("CALL registrar_nuevo_caso(%s, %s, %s, %s)", (titulo, descripcion, cliente_id, abogado_id)):
                    st.success(f"¡Caso '{titulo}' registrado exitosamente!")
                    st.balloons()
                # El error se maneja dentro de la función execute_procedure

def mostrar_gestion_entidades():
    """Muestra la interfaz para gestionar clientes y abogados."""
    st.header("👥 Gestión de Clientes y Abogados")

    tab_clientes, tab_abogados = st.tabs(["Clientes", "Abogados"])

    with tab_clientes:
        st.subheader("Registrar Nuevo Cliente")
        with st.form("nuevo_cliente_form", clear_on_submit=True):
            c_col1, c_col2 = st.columns(2)
            with c_col1:
                cliente_nombre = st.text_input("Nombre del Cliente")
                cliente_email = st.text_input("Email del Cliente")
            with c_col2:
                cliente_apellido = st.text_input("Apellido del Cliente")
                cliente_telefono = st.text_input("Teléfono del Cliente")
            
            cliente_direccion = st.text_area("Dirección")
            
            cliente_submitted = st.form_submit_button("Guardar Cliente")

            if cliente_submitted:
                if cliente_nombre and cliente_apellido and cliente_email:
                    execute_procedure(
                        "INSERT INTO clientes (nombre, apellido, email, telefono, direccion) VALUES (%s, %s, %s, %s, %s)",
                        (cliente_nombre, cliente_apellido, cliente_email, cliente_telefono, cliente_direccion)
                    )
                    st.success(f"Cliente '{cliente_nombre} {cliente_apellido}' guardado.")
                else:
                    st.error("Nombre, Apellido y Email son campos obligatorios.")
        
        st.divider()
        st.subheader("Lista de Clientes")
        clientes_existentes = fetch_data("SELECT nombre, apellido, email, telefono, direccion FROM clientes ORDER BY nombre, apellido;")
        st.dataframe(clientes_existentes, use_container_width=True)


    with tab_abogados:
        st.subheader("Registrar Nuevo Abogado")
        with st.form("nuevo_abogado_form", clear_on_submit=True):
            a_col1, a_col2 = st.columns(2)
            with a_col1:
                abogado_nombre = st.text_input("Nombre del Abogado")
                abogado_email = st.text_input("Email del Abogado")
            with a_col2:
                abogado_apellido = st.text_input("Apellido del Abogado")
                abogado_telefono = st.text_input("Teléfono del Abogado")
            
            abogado_especialidad = st.text_input("Especialidad")
            
            abogado_submitted = st.form_submit_button("Guardar Abogado")

            if abogado_submitted:
                if abogado_nombre and abogado_apellido and abogado_email:
                    execute_procedure(
                        "INSERT INTO abogados (nombre, apellido, especialidad, email, telefono) VALUES (%s, %s, %s, %s, %s)",
                        (abogado_nombre, abogado_apellido, abogado_especialidad, abogado_email, abogado_telefono)
                    )
                    st.success(f"Abogado '{abogado_nombre} {abogado_apellido}' guardado.")
                else:
                    st.error("Nombre, Apellido y Email son campos obligatorios.")

        st.divider()
        st.subheader("Lista de Abogados")
        abogados_existentes = fetch_data("SELECT nombre, apellido, especialidad, email, telefono FROM abogados ORDER BY nombre, apellido;")
        st.dataframe(abogados_existentes, use_container_width=True)

# --- Aplicación Principal ---

def main():
    st.sidebar.title("Menú de Navegación")
    st.sidebar.markdown("Seleccione un Módulo")
    
    opciones = {
        "Dashboard": "📊",
        "Crear Nuevo Caso": "📝",
        "Gestionar Clientes y Abogados": "👥"
    }
    
    seleccion = st.sidebar.radio(
        "Módulos", 
        list(opciones.keys()), 
        format_func=lambda x: f"{opciones[x]} {x}",
        label_visibility="collapsed"
    )

    st.sidebar.divider()
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
    st.title("⚖️ LegalIA - Sistema de Gestión de Casos")
    st.markdown("Bienvenido al panel de control para la gestión de casos legales. Utilice el menú de la izquierda para navegar.")
    st.divider()

    # --- Enrutador de Módulos ---
    if seleccion == "Dashboard":
        mostrar_dashboard()
    elif seleccion == "Crear Nuevo Caso":
        mostrar_crear_caso()
    elif seleccion == "Gestionar Clientes y Abogados":
        mostrar_gestion_entidades()

if __name__ == "__main__":
    main()

