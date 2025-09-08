import streamlit as st
import psycopg2
import pandas as pd
import google.generativeai as genai
from supabase import create_client, Client
import io
import re
import uuid

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
        supabase = create_client(url, key)
        
        # Verificación silenciosa de permisos
        # if "service_role" not in key:
        #     st.warning("⚠️ Recomendación: Use el Service Role Key para operaciones de storage")
        
        return supabase
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

def sanitize_filename(filename):
    """Sanitiza el nombre del archivo para ser compatible con Supabase Storage."""
    # Separar nombre y extensión
    name_parts = filename.rsplit('.', 1)
    if len(name_parts) == 2:
        name, ext = name_parts
    else:
        name, ext = filename, ""
    
    # Reemplazar caracteres problemáticos
    # Supabase Storage acepta: letras, números, guiones, guiones bajos, puntos
    sanitized_name = re.sub(r'[^a-zA-Z0-9._-]', '_', name)
    
    # Evitar nombres que empiecen o terminen con guión/guión bajo
    sanitized_name = sanitized_name.strip('_-')
    
    # Evitar nombres vacíos
    if not sanitized_name:
        sanitized_name = f"archivo_{uuid.uuid4().hex[:8]}"
    
    # Reconstruir el nombre con la extensión
    if ext:
        return f"{sanitized_name}.{ext}"
    return sanitized_name

def reset_database_connection():
    """Reinicia la conexión a la base de datos limpiando el cache."""
    st.cache_resource.clear()
    st.rerun()

def test_database_connection():
    """Prueba la conexión a la base de datos y muestra el estado."""
    conn = init_db_connection()
    if conn is None:
        st.error("❌ No se puede conectar a la base de datos. Verifique:")
        st.markdown("""
        - Las credenciales en st.secrets["database"]
        - Que el servidor de base de datos esté ejecutándose
        - La conectividad de red
        """)
        return False
    else:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                conn.commit()
            st.success("✅ Conexión a la base de datos exitosa")
            return True
        except Exception as e:
            error_str = str(e)
            if "current transaction is aborted" in error_str:
                st.error("❌ Transacción de base de datos corrupta.")
                if st.button("🔄 Reiniciar Conexión"):
                    reset_database_connection()
                st.markdown("""
                **Solución:**
                1. Haga clic en "🔄 Reiniciar Conexión" arriba
                2. O recargue la página completamente
                """)
            else:
                st.error(f"❌ Error al probar la conexión: {e}")
            return False

def run_procedure(proc_name, params=None):
    """Ejecuta un procedimiento almacenado y devuelve True si tiene éxito."""
    conn = init_db_connection()
    if conn is None: return False
    
    try:
        with conn.cursor() as cur:
            if params:
                # Crear la consulta CALL con parámetros
                placeholders = ', '.join(['%s'] * len(params))
                call_query = f"CALL {proc_name}({placeholders})"
                cur.execute(call_query, params)
            else:
                cur.execute(f"CALL {proc_name}()")
            conn.commit()
        return True
    except Exception as e:
        error_str = str(e)
        
        try:
            conn.rollback()
        except:
            # Si rollback falla, limpiar cache
            if "current transaction is aborted" in error_str:
                st.cache_resource.clear()
        
        # Manejo especial para transacciones abortadas
        if "current transaction is aborted" in error_str:
            st.cache_resource.clear()
            st.warning("⚠️ Conexión de base de datos reiniciada. Intente la operación nuevamente.")
            return False
        
        # Manejo especial para errores de tabla documentos
        if proc_name == "crear_documento" and ("does not exist" in error_str or "violates not-null constraint" in error_str):
            if "url_almacenamiento" in error_str:
                st.error("❌ La tabla 'documentos' usa 'url_almacenamiento' en lugar de 'ruta_storage'.")
                st.markdown("""
                **Solución:**
                1. Ejecute el script `fix_crear_documento_procedure.sql` para corregir el procedimiento
                2. O use el botón "🔍 Diagnosticar tabla" para ver la estructura actual
                """)
            else:
                st.error("❌ La tabla 'documentos' tiene estructura incorrecta.")
                st.markdown("""
                **Solución RÁPIDA:**
                1. Ejecute el script `fix_documentos_table.sql` en su base de datos
                2. Use el botón "🔍 Diagnosticar tabla 'documentos'" para verificar la estructura
                
                **Comando manual:**
                ```sql
                ALTER TABLE documentos ADD COLUMN IF NOT EXISTS descripcion TEXT;
                ALTER TABLE documentos ADD COLUMN IF NOT EXISTS id_caso INT;
                ALTER TABLE documentos ADD COLUMN IF NOT EXISTS ruta_storage TEXT;
                ```
                """)
        else:
            st.error(f"Error al ejecutar el procedimiento: {e}")
        return False

def run_query(query, params=None):
    """Ejecuta una consulta SQL y devuelve los resultados como DataFrame."""
    conn = init_db_connection()
    if conn is None: return pd.DataFrame()
    
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if cur.description:
                columns = [desc[0] for desc in cur.description]
                result = pd.DataFrame(cur.fetchall(), columns=columns)
            else:
                result = pd.DataFrame()
            conn.commit()  # Commit solo si todo salió bien
            return result
    except Exception as e:
        error_str = str(e)
        try:
            conn.rollback()  # Intentar rollback
        except:
            pass  # Si rollback falla, limpiar cache
        
        if "current transaction is aborted" in error_str:
            st.cache_resource.clear()
            st.warning("⚠️ Conexión reiniciada debido a transacción corrupta. Intente de nuevo.")
        else:
            st.error(f"Error al ejecutar la función: {e}")
        return pd.DataFrame()

def get_clients():
    try:
        result = run_query("SELECT id_cliente, nombre || ' ' || apellido as nombre_completo FROM clientes ORDER BY nombre;")
        if result.empty:
            # Retornar DataFrame vacío con columnas esperadas si no hay datos
            return pd.DataFrame(columns=['id_cliente', 'nombre_completo'])
        return result
    except Exception as e:
        st.error(f"Error al obtener clientes: {e}")
        return pd.DataFrame(columns=['id_cliente', 'nombre_completo'])

def get_lawyers():
    try:
        result = run_query("SELECT id_abogado, nombre || ' ' || apellido as nombre_completo FROM abogados ORDER BY nombre;")
        if result.empty:
            # Retornar DataFrame vacío con columnas esperadas si no hay datos
            return pd.DataFrame(columns=['id_abogado', 'nombre_completo'])
        return result
    except Exception as e:
        st.error(f"Error al obtener abogados: {e}")
        return pd.DataFrame(columns=['id_abogado', 'nombre_completo'])

def get_cases_detailed():
    return run_query("SELECT * FROM obtener_casos_detallados();")

def get_documents_for_case(case_id):
    """Obtiene documentos de un caso, manejando diferentes nombres de columnas."""
    
    try:
        # Primero determinar qué columnas existen
        structure_query = """
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'documentos'
        AND column_name IN ('ruta_storage', 'url_almacenamiento')
        """
        
        columns_result = run_query(structure_query)
        if columns_result.empty:
            return pd.DataFrame()
        
        available_columns = columns_result['column_name'].tolist()
        
        # Usar la columna correcta
        if 'url_almacenamiento' in available_columns:
            path_column = 'url_almacenamiento'
        elif 'ruta_storage' in available_columns:
            path_column = 'ruta_storage'
        else:
            return pd.DataFrame()
        
        # Query simple usando la columna correcta
        query = f"""
        SELECT 
            id_documento,
            nombre_archivo,
            COALESCE(descripcion, '') as descripcion,
            fecha_subida,
            {path_column} as ruta_storage
        FROM documentos 
        WHERE id_caso = %s 
        ORDER BY fecha_subida DESC;
        """
        
        result = run_query(query, (case_id,))
        
        # Debug: mostrar información si está vacío
        if result.empty:
            st.warning(f"🔍 Debug: No se encontraron documentos para caso {case_id} usando columna '{path_column}'")
        
        return result
        
    except Exception as e:
        st.error(f"Error al obtener documentos para caso {case_id}: {e}")
        return pd.DataFrame()

def check_documentos_table_structure():
    """Verifica la estructura de la tabla documentos y muestra información útil."""
    try:
        # Consulta más detallada incluyendo constraints
        query = """
        SELECT 
            column_name, 
            data_type, 
            is_nullable,
            column_default,
            CASE WHEN is_nullable = 'NO' THEN 'Required' ELSE 'Optional' END as required
        FROM information_schema.columns
        WHERE table_name = 'documentos'
        ORDER BY ordinal_position;
        """
        result = run_query(query)
        if not result.empty:
            st.info("📋 Estructura actual de la tabla 'documentos':")
            st.dataframe(result, use_container_width=True)
            
            # Mostrar información específica sobre columnas problemáticas
            required_cols = result[result['is_nullable'] == 'NO']['column_name'].tolist()
            if required_cols:
                st.warning(f"⚠️ Columnas requeridas (NOT NULL): {', '.join(required_cols)}")
        else:
            st.error("❌ La tabla 'documentos' no existe")
        return result
    except Exception as e:
        st.error(f"Error al verificar estructura: {e}")
        return pd.DataFrame()

def check_file_exists_in_supabase(storage_path):
    """Verifica si un archivo existe en Supabase Storage."""
    try:
        supabase_client = init_supabase_client()
        if not supabase_client:
            return False
        
        # Separar directorio y nombre del archivo
        # storage_path = "4/GobiernoTI.pdf" -> directory = "4", filename = "GobiernoTI.pdf"
        parts = storage_path.split('/')
        if len(parts) != 2:
            return False
        
        directory, filename = parts
        
        # Listar archivos en el directorio
        response = supabase_client.storage.from_("documentos_casos").list(path=directory)
        
        # Buscar el archivo específico en la lista
        for file_item in response:
            if file_item.get('name') == filename:
                return True
        
        return False
    except Exception as e:
        # Debug: mostrar error si es necesario
        return False

def update_document_path(id_documento, new_path):
    """Actualiza la ruta de un documento específico."""
    try:
        conn = init_db_connection()
        if conn is None:
            return False
        
        with conn.cursor() as cur:
            # Verificar si usar ruta_storage o url_almacenamiento
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'documentos'
                AND column_name IN ('ruta_storage', 'url_almacenamiento')
            """)
            columns = [row[0] for row in cur.fetchall()]
            
            if 'ruta_storage' in columns:
                column_name = 'ruta_storage'
            elif 'url_almacenamiento' in columns:
                column_name = 'url_almacenamiento'
            else:
                return False
            
            # Actualizar la ruta
            update_query = f"UPDATE documentos SET {column_name} = %s WHERE id_documento = %s"
            cur.execute(update_query, (new_path, id_documento))
            conn.commit()
            
            return cur.rowcount > 0
            
    except Exception as e:
        st.error(f"Error al actualizar ruta: {e}")
        return False

def fix_missing_file_paths():
    """Intenta arreglar documentos que no tienen ruta de archivo."""
    st.info("🔧 Buscando y corrigiendo documentos sin ruta...")
    
    try:
        # Buscar documentos sin ruta
        query = """
        SELECT id_documento, nombre_archivo, id_caso,
               COALESCE(ruta_storage, url_almacenamiento) as ruta_actual
        FROM documentos 
        WHERE (ruta_storage IS NULL OR ruta_storage = '') 
           AND (url_almacenamiento IS NULL OR url_almacenamiento = '')
        """
        
        missing_paths = run_query(query)
        
        if missing_paths.empty:
            st.success("✅ Todos los documentos tienen ruta de archivo")
            return
        
        st.warning(f"⚠️ Encontrados {len(missing_paths)} documentos sin ruta")
        
        # Intentar reconstruir las rutas
        fixed_count = 0
        for idx, doc in missing_paths.iterrows():
            # Intentar generar la ruta esperada
            expected_path = f"{doc['id_caso']}/{doc['nombre_archivo']}"
            
            # Verificar si el archivo existe en esa ruta
            if check_file_exists_in_supabase(expected_path):
                # Actualizar la ruta en la base de datos
                update_query = """
                UPDATE documentos 
                SET ruta_storage = %s 
                WHERE id_documento = %s
                """
                
                # Para UPDATE, usar una función específica
                success = update_document_path(doc['id_documento'], expected_path)
                if success:
                    fixed_count += 1
                    st.success(f"✅ Arreglado: {doc['nombre_archivo']} → {expected_path}")
            else:
                st.error(f"❌ No encontrado: {doc['nombre_archivo']} (esperado en {expected_path})")
        
        if fixed_count > 0:
            st.success(f"🎉 Se arreglaron {fixed_count} documentos")
        else:
            st.warning("⚠️ No se pudieron arreglar automáticamente los documentos")
            
    except Exception as e:
        st.error(f"Error al arreglar rutas: {e}")

def create_document_fallback(nombre_archivo, descripcion, id_caso, ruta_storage):
    """Función de respaldo para crear documentos cuando el procedimiento falla."""
    
    # Primero verificar qué columnas existen
    structure = check_documentos_table_structure()
    
    if structure.empty:
        st.error("❌ No se puede crear documento: tabla no encontrada")
        return False
    
    # Obtener columnas disponibles
    available_columns = structure['column_name'].tolist()
    
    # Construir query dinámicamente basado en columnas disponibles
    columns = []
    values = []
    params = []
    
    if 'nombre_archivo' in available_columns:
        columns.append('nombre_archivo')
        values.append('%s')
        params.append(nombre_archivo)
    
    if 'descripcion' in available_columns:
        columns.append('descripcion')
        values.append('%s')
        params.append(descripcion)
    
    if 'id_caso' in available_columns:
        columns.append('id_caso')
        values.append('%s')
        params.append(id_caso)
    
    # Manejar tanto ruta_storage como url_almacenamiento
    if 'ruta_storage' in available_columns:
        columns.append('ruta_storage')
        values.append('%s')
        params.append(ruta_storage)
    elif 'url_almacenamiento' in available_columns:
        columns.append('url_almacenamiento')
        values.append('%s')
        params.append(ruta_storage)  # Usar el mismo valor
    
    if 'fecha_subida' in available_columns:
        columns.append('fecha_subida')
        values.append('CURRENT_TIMESTAMP')
        # No agregamos parámetro para CURRENT_TIMESTAMP
    
    if not columns:
        st.error("❌ No hay columnas compatibles en la tabla documentos")
        return False
    
    try:
        # Construir e ejecutar query
        columns_str = ', '.join(columns)
        values_str = ', '.join(values)
        query = f"INSERT INTO documentos ({columns_str}) VALUES ({values_str})"
        
        conn = init_db_connection()
        if conn is None:
            return False
            
        with conn.cursor() as cur:
            cur.execute(query, params)
            conn.commit()
        
        missing_columns = [col for col in ['nombre_archivo', 'descripcion', 'id_caso', 'ruta_storage'] 
                          if col not in available_columns]
        
        if missing_columns:
            st.warning(f"⚠️ Documento guardado, pero faltan columnas: {', '.join(missing_columns)}")
            st.markdown("**Ejecute el script `fix_documentos_table.sql` para completar la estructura**")
        
        return True
        
    except Exception as e:
        st.error(f"Error al guardar documento: {e}")
        return False

# --- Interfaz de Usuario (Frontend) ---

st.sidebar.title("Menú de Navegación")
st.sidebar.markdown("Seleccione un Módulo")
page = st.sidebar.radio("Módulos", ["Dashboard", "Crear Nuevo Caso", "Gestión Documental", "Gestionar Clientes y Abogados"], label_visibility="hidden")

st.sidebar.markdown("---")

# Botón de reinicio de conexión en la barra lateral
if st.sidebar.button("🔄 Reiniciar Conexión DB"):
    reset_database_connection()

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
    
    # Probar conexión a la base de datos
    if not test_database_connection():
        st.stop()
    
    cases = get_cases_detailed()

    if cases.empty:
        st.info("No hay casos registrados en el sistema.")
    else:
        for index, case in cases.iterrows():
            with st.expander(f"**{case['titulo']}** (Cliente: {case['cliente']}) - Estado: {case['estado']}"):
                col1, col2 = st.columns([3, 2])
                with col1:
                    st.markdown(f"**Abogado Asignado:** {case['abogado']}")
                    # Manejar formato de fecha independientemente del tipo
                    try:
                        if hasattr(case['fecha_apertura'], 'strftime'):
                            fecha_str = case['fecha_apertura'].strftime('%d/%m/%Y')
                        else:
                            fecha_str = str(case['fecha_apertura'])
                        st.markdown(f"**Fecha de Apertura:** {fecha_str}")
                    except Exception:
                        st.markdown(f"**Fecha de Apertura:** {case['fecha_apertura']}")
                    st.markdown(f"**Descripción:**\n{case['descripcion']}")

                    if model and st.button("Generar Resumen con IA", key=f"sum_{case['id_caso']}"):
                        with st.spinner("La IA está analizando el caso..."):
                            try:
                                response = model.generate_content(
                                    f"Resume el siguiente caso legal en 2 o 3 puntos clave: Título: {case['titulo']}. Descripción: {case['descripcion']}."
                                )
                                st.success("**Resumen por IA:**")
                                st.markdown(response.text)
                            except Exception as e:
                                st.error(f"No se pudo generar el resumen: {e}")

                with col2:
                    st.subheader("Estado del Caso")
                    status_options = ["Abierto", "En Progreso", "Cerrado", "Archivado"]
                    try:
                        current_index = status_options.index(case['estado']) if case['estado'] in status_options else 0
                    except (KeyError, ValueError):
                        current_index = 0
                    
                    new_status = st.selectbox(
                        "Cambiar estado",
                        status_options,
                        index=current_index,
                        key=f"status_{case['id_caso']}"
                    )
                    if st.button("Actualizar Estado", key=f"upd_{case['id_caso']}"):
                        if run_procedure("actualizar_estado_caso", (case['id_caso'], new_status)):
                            st.toast("Estado actualizado.")
                            st.rerun()
                
                st.markdown("---")
                st.subheader("Documentos del Caso")
                documents = get_documents_for_case(case['id_caso'])
                
                
                if documents.empty:
                    st.write("No hay documentos asociados a este caso.")
                else:
                    supabase_client = init_supabase_client()
                    for idx, doc in documents.iterrows():
                        # Usar un contenedor para cada documento
                        with st.container():
                            st.markdown("---")
                            
                            doc_col1, doc_col2 = st.columns([3, 1])
                            with doc_col1:
                                # Manejar formato de fecha para documentos
                                try:
                                    if hasattr(doc['fecha_subida'], 'strftime'):
                                        fecha_str = doc['fecha_subida'].strftime('%d/%m/%Y %H:%M')
                                    else:
                                        fecha_str = str(doc['fecha_subida'])
                                    st.write(f"📄 **{doc['nombre_archivo']}** - Subido: {fecha_str}")
                                except Exception:
                                    st.write(f"📄 **{doc['nombre_archivo']}** - Subido: {doc['fecha_subida']}")
                            with doc_col2:
                                if supabase_client:
                                    try:
                                        # Verificar que tenemos la ruta del storage
                                        ruta_valor = doc.get('ruta_storage', None)
                                        
                                        if pd.isna(ruta_valor) or ruta_valor is None or str(ruta_valor).strip() == '' or str(ruta_valor) == 'nan':
                                            st.error("❌ Sin ruta de archivo")
                                        else:
                                            storage_path = str(doc['ruta_storage']).strip()
                                            
                                            # Verificar si el archivo existe antes de crear el enlace
                                            file_exists = check_file_exists_in_supabase(storage_path)
                                            
                                            if not file_exists:
                                                st.warning("⚠️ Archivo no encontrado en storage")
                                                if st.button(f"🔍 Debug", key=f"debug_{doc.get('id_documento', 'unknown')}"):
                                                    st.json({
                                                        "archivo": doc.get('nombre_archivo', 'N/A'),
                                                        "ruta_storage": storage_path,
                                                        "bucket": "documentos_casos",
                                                        "existe": file_exists
                                                    })
                                            else:
                                                # Crear URL firmada
                                                response = supabase_client.storage.from_("documentos_casos").create_signed_url(storage_path, 3600)  # 1 hora
                                                
                                                if response and 'signedURL' in response:
                                                    signed_url = response['signedURL']
                                                    
                                                    # Botón de descarga
                                                    st.link_button("📥 Descargar", signed_url, help="Descargar archivo", use_container_width=True)
                                                    
                                                else:
                                                    st.error(f"❌ No se pudo generar URL: {response}")
                                                    
                                    except Exception as e:
                                        error_msg = str(e)
                                        st.error(f"❌ Error: {error_msg}")
                                else:
                                    st.error("❌ Cliente Supabase no disponible")
                            
                            # Vista previa automática para PDFs (fuera de las columnas)
                            if supabase_client:
                                ruta_valor = doc.get('ruta_storage', None)
                                if not (pd.isna(ruta_valor) or ruta_valor is None or str(ruta_valor).strip() == ''):
                                    storage_path = str(doc['ruta_storage']).strip()
                                    file_exists = check_file_exists_in_supabase(storage_path)
                                    
                                    if file_exists and doc['nombre_archivo'].lower().endswith('.pdf'):
                                        try:
                                            response = supabase_client.storage.from_("documentos_casos").create_signed_url(storage_path, 3600)
                                            if response and 'signedURL' in response:
                                                with st.expander("👁️ Vista Previa del PDF", expanded=False):
                                                    st.markdown(f"""
                                                    <iframe src="{response['signedURL']}" width="100%" height="600" style="border: 1px solid #ccc;">
                                                        <p>Su navegador no soporta iframes. <a href="{response['signedURL']}" target="_blank">Haga clic aquí para abrir el PDF</a>.</p>
                                                    </iframe>
                                                    """, unsafe_allow_html=True)
                                        except:
                                            pass


# --- Página de Creación de Casos ---
elif page == "Crear Nuevo Caso":
    st.header("➕ Crear Nuevo Caso")
    
    # Verificar conexión antes de continuar
    if not test_database_connection():
        st.stop()
    
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
                if run_procedure("crear_caso", (case_title, case_description, client_id, lawyer_id)):
                    st.success("¡Caso creado exitosamente!")

# --- Página de Gestión Documental ---
elif page == "Gestión Documental":
    st.header("📂 Gestión Documental")
    
    # Verificar conexión antes de continuar
    if not test_database_connection():
        st.stop()
    
    # Herramientas de diagnóstico (colapsadas por defecto)
    with st.expander("🔧 Herramientas de Diagnóstico", expanded=False):
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔍 Diagnosticar tabla 'documentos'"):
                check_documentos_table_structure()
        with col2:
            if st.button("📋 Ver documentos guardados"):
                # Mostrar todos los documentos con sus rutas
                docs_query = """
                SELECT id_documento, nombre_archivo, 
                       CASE 
                           WHEN ruta_storage IS NOT NULL AND ruta_storage != '' THEN ruta_storage
                           WHEN url_almacenamiento IS NOT NULL AND url_almacenamiento != '' THEN url_almacenamiento
                           ELSE 'Sin ruta'
                       END as ruta_archivo,
                       id_caso
                FROM documentos 
                ORDER BY id_documento DESC
                LIMIT 10;
                """
                try:
                    docs_result = run_query(docs_query)
                    if not docs_result.empty:
                        st.dataframe(docs_result, use_container_width=True)
                        
                        # Mostrar cuántos documentos sin ruta hay
                        sin_ruta = docs_result[docs_result['ruta_archivo'] == 'Sin ruta'].shape[0]
                        if sin_ruta > 0:
                            st.warning(f"⚠️ {sin_ruta} documentos sin ruta de archivo")
                    else:
                        st.info("No hay documentos en la base de datos")
                except Exception as e:
                    st.error(f"Error al consultar documentos: {e}")
        with col3:
            if st.button("🔧 Arreglar rutas faltantes"):
                fix_missing_file_paths()

        # Botón adicional para listar archivos en Supabase
        if st.button("📂 Ver archivos en Supabase Storage"):
            supabase_client = init_supabase_client()
            if supabase_client:
                try:
                    st.info("🔍 Listando archivos en bucket 'documentos_casos'...")
                    
                    # Listar archivos en el root del bucket
                    files = supabase_client.storage.from_("documentos_casos").list()
                    
                    if files:
                        st.success(f"📁 Encontrados {len(files)} elementos:")
                        for file_item in files:
                            st.write(f"- {file_item}")
                            
                            # Si es una carpeta, listar su contenido
                            if file_item.get('name') and '.' not in file_item.get('name', ''):
                                try:
                                    folder_files = supabase_client.storage.from_("documentos_casos").list(path=file_item['name'])
                                    for sub_file in folder_files:
                                        st.write(f"  └─ {file_item['name']}/{sub_file.get('name', sub_file)}")
                                except:
                                    pass
                    else:
                        st.warning("📁 El bucket está vacío o no se pueden listar archivos")
                        
                except Exception as e:
                    st.error(f"❌ Error al listar archivos: {e}")
                    if "401" in str(e) or "403" in str(e):
                        st.markdown("""
                        **Causa probable:** Necesita Service Role Key para listar archivos
                        1. Vaya a Supabase → Settings → API
                        2. Copie el Service Role Key (no el Anon Key) 
                        3. Actualice sus secrets de Streamlit
                        """)
            else:
                st.error("❌ Cliente Supabase no disponible")

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
                original_file_name = uploaded_file.name
                
                # Sanitizar el nombre del archivo para Supabase Storage
                sanitized_file_name = sanitize_filename(original_file_name)
                storage_path = f"{case_id}/{sanitized_file_name}"

                supabase_client = init_supabase_client()
                if supabase_client:
                    try:
                        with st.spinner(f"Subiendo '{original_file_name}'..."):
                            supabase_client.storage.from_("documentos_casos").upload(file=file_bytes, path=storage_path, file_options={"content-type": uploaded_file.type})
                            # Guardar con el nombre original en la base de datos para mostrar al usuario
                            success = run_procedure("crear_documento", (original_file_name, doc_description, case_id, storage_path))
                            
                            # Si el procedimiento falla, usar la función de fallback
                            if not success:
                                success = create_document_fallback(original_file_name, doc_description, case_id, storage_path)
                            
                            if success:
                                st.success(f"¡Documento '{original_file_name}' subido y asociado al caso '{selected_case_title}'!")
                                if original_file_name != sanitized_file_name:
                                    st.info(f"Nota: El archivo se guardó como '{sanitized_file_name}' en el almacenamiento para compatibilidad.")
                    except Exception as e:
                        error_str = str(e)
                        if "duplicate" in error_str:
                             st.warning(f"Un archivo con el nombre '{sanitized_file_name}' ya existe. Por favor, cambie el nombre del archivo.")
                        elif "Unauthorized" in error_str or "403" in error_str:
                            st.error("❌ Error de permisos de Supabase Storage. Soluciones:")
                            st.markdown("""
                            **Opción 1: Actualizar configuración**
                            - Use el Service Role Key en lugar del Anon Key en sus secrets
                            
                            **Opción 2: Modificar políticas RLS**
                            - Vaya a Supabase → Storage → Policies
                            - Cree políticas que permitan acceso público al bucket 'documentos_casos'
                            """)
                        else:
                            st.error(f"Error al subir el archivo: {e}")
            else:
                st.error("Por favor, seleccione un caso y un archivo para subir.")


# --- Página de Gestión de Clientes y Abogados ---
elif page == "Gestionar Clientes y Abogados":
    st.header("👥 Gestión de Clientes y Abogados")
    
    # Verificar conexión antes de continuar
    if not test_database_connection():
        st.stop()

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
                    if run_procedure("crear_cliente", (nombre_cli, apellido_cli, email_cli, telefono_cli, direccion_cli)):
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
                    if run_procedure("crear_abogado", (nombre_abo, apellido_abo, especialidad_abo, email_abo, telefono_abo)):
                        st.success("¡Abogado guardado con éxito!")
                        st.rerun()

        st.markdown("---")
        st.subheader("Lista de Abogados")
        abogados_df = run_query("SELECT nombre, apellido, especialidad, email, telefono FROM abogados ORDER BY nombre, apellido;")
        st.dataframe(abogados_df, use_container_width=True)