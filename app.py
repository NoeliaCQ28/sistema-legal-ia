import streamlit as st
import psycopg2
import pandas as pd
import google.generativeai as genai
from supabase import create_client, Client
import io
import re
import uuid
import bcrypt
import jwt
from datetime import datetime, timedelta
from st_supabase_connection import SupabaseConnection

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

# --- Conexión a Supabase para Autenticación ---
@st.cache_resource
def init_supabase_auth_connection():
    """Inicializa la conexión a Supabase para autenticación usando st.connection"""
    try:
        # Usar la configuración directamente de secrets
        supabase_url = st.secrets["connections"]["supabase"]["url"]
        supabase_key = st.secrets["connections"]["supabase"]["key"]
        
        # Crear la conexión pasando los parámetros explícitamente
        return st.connection(
            "supabase", 
            type=SupabaseConnection,
            url=supabase_url,
            key=supabase_key
        )
    except Exception as e:
        st.error(f"Error al conectar con Supabase para autenticación: {e}")
        return None

@st.cache_resource
def init_supabase_direct():
    """Conexión directa a Supabase como fallback"""
    try:
        supabase_url = st.secrets["connections"]["supabase"]["url"]
        supabase_key = st.secrets["connections"]["supabase"]["key"]
        return create_client(supabase_url, supabase_key)
    except Exception as e:
        st.error(f"Error en conexión directa a Supabase: {e}")
        return None

# --- Funciones de Autenticación ---
def hash_password(password: str) -> str:
    """Genera hash de contraseña usando bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verifica contraseña contra hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str) -> str:
    """Crea JWT token para el usuario"""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    # Usar una clave secreta simple para JWT (en producción usar st.secrets)
    secret_key = "legalai_secret_key_2024"
    return jwt.encode(payload, secret_key, algorithm='HS256')

def verify_jwt_token(token: str) -> dict:
    """Verifica y decodifica JWT token"""
    try:
        secret_key = "legalai_secret_key_2024"
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# --- Sistema de Control de Acceso Basado en Roles (RBAC) ---
def get_role_permissions():
    """Define los permisos para cada rol"""
    return {
        "administrador": {
            "dashboard": True,
            "crear_caso": True,
            "gestion_documental": True,
            "gestionar_usuarios": True,
            "mi_perfil": True,
            "reportes": True,
            "agenda": True,
            "notificaciones": True,
            "tareas": True,
            "ver_todos_casos": True,
            "editar_todos_casos": True,
            "eliminar_casos": True,
            "gestionar_roles": True
        },
        "socio": {
            "dashboard": True,
            "crear_caso": True,
            "gestion_documental": True,
            "gestionar_usuarios": False,
            "mi_perfil": True,
            "reportes": True,
            "agenda": True,
            "notificaciones": True,
            "tareas": True,
            "ver_todos_casos": True,
            "editar_todos_casos": True,
            "eliminar_casos": False,
            "gestionar_roles": False
        },
        "abogado_senior": {
            "dashboard": True,
            "crear_caso": True,
            "gestion_documental": True,
            "gestionar_usuarios": False,
            "mi_perfil": True,
            "reportes": True,
            "agenda": True,
            "notificaciones": True,
            "tareas": True,
            "ver_todos_casos": False,
            "editar_todos_casos": False,
            "eliminar_casos": False,
            "gestionar_roles": False
        },
        "abogado_junior": {
            "dashboard": True,
            "crear_caso": False,
            "gestion_documental": True,
            "gestionar_usuarios": False,
            "mi_perfil": True,
            "reportes": False,
            "agenda": True,
            "notificaciones": True,
            "tareas": True,
            "ver_todos_casos": False,
            "editar_todos_casos": False,
            "eliminar_casos": False,
            "gestionar_roles": False
        },
        "cliente": {
            "dashboard": True,
            "crear_caso": False,
            "gestion_documental": False,
            "gestionar_usuarios": False,
            "mi_perfil": True,
            "reportes": False,
            "agenda": False,
            "notificaciones": True,
            "tareas": False,
            "ver_todos_casos": False,
            "editar_todos_casos": False,
            "eliminar_casos": False,
            "gestionar_roles": False
        }
    }

def has_permission(permission: str) -> bool:
    """Verifica si el usuario actual tiene un permiso específico"""
    if not check_authentication():
        return False
    
    user_data = st.session_state.get('user_data', {})
    user_role = user_data.get('rol', 'cliente').lower()
    
    # Normalizar nombres de roles
    role_mapping = {
        'admin': 'administrador',
        'administrador': 'administrador',
        'socio': 'socio',
        'director': 'socio',
        'abogado_senior': 'abogado_senior',
        'senior': 'abogado_senior',
        'abogado_junior': 'abogado_junior',
        'junior': 'abogado_junior',
        'cliente': 'cliente',
        'usuario': 'cliente'  # Por defecto, usuario = cliente
    }
    
    normalized_role = role_mapping.get(user_role, 'cliente')
    permissions = get_role_permissions()
    
    return permissions.get(normalized_role, {}).get(permission, False)

def require_permission(permission: str):
    """Decorator/helper para requerir un permiso específico"""
    if not has_permission(permission):
        st.error("🚫 No tienes permisos para acceder a esta funcionalidad")
        st.info(f"Permiso requerido: {permission}")
        st.stop()

def get_user_role() -> str:
    """Obtiene el rol del usuario actual"""
    if not check_authentication():
        return "invitado"
    
    user_data = st.session_state.get('user_data', {})
    return user_data.get('rol', 'cliente').lower()

def get_available_roles() -> list:
    """Retorna la lista de roles disponibles"""
    return ["administrador", "socio", "abogado_senior", "abogado_junior", "cliente"]

def get_role_display_name(role: str) -> str:
    """Convierte el nombre técnico del rol a nombre para mostrar"""
    role_names = {
        "administrador": "🔧 Administrador",
        "socio": "⚖️ Socio/Director", 
        "abogado_senior": "👨‍💼 Abogado Senior",
        "abogado_junior": "👩‍💼 Abogado Junior",
        "cliente": "💼 Cliente"
    }
    return role_names.get(role.lower(), role)

def register_user(email: str, password: str, nombre_completo: str, rol: str = "cliente") -> bool:
    """Registra un nuevo usuario en Supabase Auth y en la tabla perfiles"""
    try:
        # Intentar con st.connection primero
        supabase_conn = init_supabase_auth_connection()
        
        # Si falla, usar conexión directa
        if not supabase_conn:
            supabase_client = init_supabase_direct()
            if not supabase_client:
                return False
        else:
            supabase_client = supabase_conn.client
        
        # Registrar en Supabase Auth
        auth_response = supabase_client.auth.sign_up({
            "email": email,
            "password": password
        })
        
        if auth_response.user:
            user_id = auth_response.user.id
            
            # Crear perfil en nuestra tabla
            profile_data = {
                "id": user_id,
                "nombre_completo": nombre_completo,
                "rol": rol.lower()
            }
            
            supabase_client.table("perfiles").insert(profile_data).execute()
            
            return True
        return False
        
    except Exception as e:
        st.error(f"Error al registrar usuario: {e}")
        return False

def login_user(email: str, password: str) -> dict:
    """Autentica usuario con Supabase Auth"""
    try:
        # Intentar con st.connection primero
        supabase_conn = init_supabase_auth_connection()
        
        # Si falla, usar conexión directa
        if not supabase_conn:
            supabase_client = init_supabase_direct()
            if not supabase_client:
                return None
        else:
            supabase_client = supabase_conn.client
        
        # Intentar login con Supabase Auth
        auth_response = supabase_client.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        
        if auth_response.user:
            user_id = auth_response.user.id
            
            # Obtener perfil del usuario
            profile_response = supabase_client.table("perfiles").select("*").eq("id", user_id).execute()
            
            if profile_response.data:
                profile = profile_response.data[0]
                return {
                    "id": user_id,
                    "email": email,
                    "nombre_completo": profile.get("nombre_completo", ""),
                    "rol": profile.get("rol", "usuario"),
                    "token": create_jwt_token(user_id, email)
                }
        return None
        
    except Exception as e:
        st.error(f"Error al iniciar sesión: {e}")
        return None

def refresh_user_data():
    """Refresca los datos del usuario desde la base de datos"""
    try:
        if not st.session_state.get('authenticated', False):
            st.warning("⚠️ Usuario no autenticado")
            return False
            
        user_data = st.session_state.get('user_data', {})
        
        # Intentar obtener ID de diferentes maneras
        user_id = user_data.get('id') or user_data.get('user_id')
        
        # Intentar obtener desde auth token si existe
        if not user_id:
            token = user_data.get('token')
            if token:
                try:
                    import jwt
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    user_id = decoded.get('user_id') or decoded.get('sub')
                except:
                    pass
        
        if not user_id:
            st.error(f"❌ No se encontró ID de usuario. Intente cerrar sesión y volver a iniciar.")
            return False
            
        # Obtener datos actualizados del perfil
        conn = init_db_connection()
        if conn:
            with conn.cursor() as cur:
                cur.execute("SELECT nombre_completo, rol FROM perfiles WHERE id = %s", (user_id,))
                perfil = cur.fetchone()
                
                if perfil:
                    # Actualizar session state con datos frescos
                    old_role = st.session_state.user_data.get('rol', 'N/A')
                    new_role = perfil[1]
                    
                    st.session_state.user_data.update({
                        'nombre_completo': perfil[0],
                        'rol': new_role
                    })
                    
                    # Log del cambio
                    if old_role != new_role:
                        st.success(f"🔄 Rol actualizado: {old_role} → {new_role}")
                    
                    return True
                else:
                    st.error(f"❌ No se encontró perfil para el usuario ID: {user_id}")
                    return False
        else:
            st.error("❌ No se pudo conectar a la base de datos")
            return False
        
    except Exception as e:
        st.error(f"Error al refrescar datos del usuario: {e}")
        return False

def migrar_clientes_a_perfiles():
    """Migra datos de la tabla clientes a perfiles con rol cliente"""
    try:
        conn = init_db_connection()
        
        # Usar la conexión de servicio para operaciones admin
        try:
            supabase_url = st.secrets["supabase"]["url"]
            supabase_service_key = st.secrets["supabase"]["service_role_key"]
            supabase_client = create_client(supabase_url, supabase_service_key)
        except Exception as e:
            st.error(f"Error al conectar con Supabase como admin: {e}")
            return
        
        if conn and supabase_client:
            with conn.cursor() as cur:
                # Obtener clientes que no tienen perfil
                cur.execute("""
                    SELECT c.id_cliente, c.nombre, c.apellido, c.email 
                    FROM clientes c 
                    WHERE c.email IS NOT NULL 
                    AND c.email NOT IN (
                        SELECT COALESCE(nombre_completo, '') FROM perfiles 
                        WHERE nombre_completo ILIKE '%' || c.email || '%'
                    )
                    LIMIT 5
                """)
                clientes = cur.fetchall()
                
                if not clientes:
                    st.info("ℹ️ No hay clientes nuevos para migrar")
                    return
                
                migrados = 0
                errores = 0
                
                st.info(f"🔄 Intentando migrar {len(clientes)} clientes...")
                
                for cliente in clientes:
                    try:
                        email = cliente[3].strip().lower()
                        nombre_completo = f"{cliente[1]} {cliente[2]}" if cliente[1] and cliente[2] else f"Cliente {email}"
                        
                        st.info(f"📝 Procesando: {nombre_completo} ({email})")
                        
                        # Crear usuario en Supabase Auth con contraseña por defecto
                        auth_response = supabase_client.auth.admin.create_user({
                            "email": email,
                            "password": "1234567",
                            "email_confirm": True
                        })
                        
                        if auth_response.user:
                            user_id = auth_response.user.id
                            
                            # Crear perfil en la tabla perfiles
                            cur.execute("""
                                INSERT INTO perfiles (id, nombre_completo, rol) 
                                VALUES (%s, %s, 'cliente')
                                ON CONFLICT (id) DO UPDATE SET 
                                nombre_completo = EXCLUDED.nombre_completo,
                                rol = 'cliente'
                            """, (user_id, nombre_completo))
                            
                            migrados += 1
                            st.success(f"✅ Migrado: {nombre_completo} ({email})")
                        else:
                            st.warning(f"⚠️ No se pudo crear usuario para {email}")
                            errores += 1
                        
                    except Exception as e:
                        errores += 1
                        error_msg = str(e)
                        if "User already registered" in error_msg:
                            st.warning(f"⚠️ {email} ya está registrado")
                        else:
                            st.warning(f"⚠️ Error con {cliente[3]}: {error_msg[:100]}")
                        continue
                
                conn.commit()
                
                if migrados > 0:
                    st.success(f"🎉 Se migraron {migrados} clientes exitosamente")
                    st.info("🔑 Contraseña por defecto: **1234567**")
                    st.info("💡 Los usuarios pueden cambiar su contraseña al iniciar sesión")
                
                if errores > 0:
                    st.warning(f"⚠️ {errores} clientes no se pudieron migrar")
                
    except Exception as e:
        st.error(f"Error en migración de clientes: {e}")
        st.exception(e)

def migrar_abogados_a_perfiles():
    """Migra datos de la tabla abogados a perfiles con rol abogado_junior"""
    try:
        conn = init_db_connection()
        
        # Usar la conexión de servicio para operaciones admin
        try:
            supabase_url = st.secrets["supabase"]["url"]
            supabase_service_key = st.secrets["supabase"]["service_role_key"]
            supabase_client = create_client(supabase_url, supabase_service_key)
        except Exception as e:
            st.error(f"Error al conectar con Supabase como admin: {e}")
            return
        
        if conn and supabase_client:
            with conn.cursor() as cur:
                # Obtener abogados que no tienen perfil
                cur.execute("""
                    SELECT a.id_abogado, a.nombre, a.apellido, a.email, a.especialidad 
                    FROM abogados a 
                    WHERE a.email IS NOT NULL 
                    AND a.email NOT IN (
                        SELECT COALESCE(nombre_completo, '') FROM perfiles 
                        WHERE nombre_completo ILIKE '%' || a.email || '%'
                    )
                    LIMIT 5
                """)
                abogados = cur.fetchall()
                
                if not abogados:
                    st.info("ℹ️ No hay abogados nuevos para migrar")
                    return
                
                migrados = 0
                errores = 0
                
                st.info(f"🔄 Intentando migrar {len(abogados)} abogados...")
                
                for abogado in abogados:
                    try:
                        email = abogado[3].strip().lower()
                        nombre_completo = f"{abogado[1]} {abogado[2]}" if abogado[1] and abogado[2] else f"Abogado {email}"
                        if abogado[4]:  # especialidad
                            nombre_completo += f" - {abogado[4]}"
                        
                        st.info(f"📝 Procesando: {nombre_completo} ({email})")
                        
                        # Crear usuario en Supabase Auth con contraseña por defecto
                        auth_response = supabase_client.auth.admin.create_user({
                            "email": email,
                            "password": "1234567",
                            "email_confirm": True
                        })
                        
                        if auth_response.user:
                            user_id = auth_response.user.id
                            
                            # Crear perfil en la tabla perfiles
                            cur.execute("""
                                INSERT INTO perfiles (id, nombre_completo, rol) 
                                VALUES (%s, %s, 'abogado_junior')
                                ON CONFLICT (id) DO UPDATE SET 
                                nombre_completo = EXCLUDED.nombre_completo,
                                rol = 'abogado_junior'
                            """, (user_id, nombre_completo))
                            
                            migrados += 1
                            st.success(f"✅ Migrado: {nombre_completo} ({email})")
                        else:
                            st.warning(f"⚠️ No se pudo crear usuario para {email}")
                            errores += 1
                        
                    except Exception as e:
                        errores += 1
                        error_msg = str(e)
                        if "User already registered" in error_msg:
                            st.warning(f"⚠️ {email} ya está registrado")
                        else:
                            st.warning(f"⚠️ Error con {abogado[3]}: {error_msg[:100]}")
                        continue
                
                conn.commit()
                
                if migrados > 0:
                    st.success(f"🎉 Se migraron {migrados} abogados exitosamente")
                    st.info("🔑 Contraseña por defecto: **1234567**")
                    st.info("💡 Los usuarios pueden cambiar su contraseña al iniciar sesión")
                
                if errores > 0:
                    st.warning(f"⚠️ {errores} abogados no se pudieron migrar")
                
    except Exception as e:
        st.error(f"Error en migración de abogados: {e}")
        st.exception(e)

def logout_user():
    """Cierra sesión del usuario"""
    try:
        # Intentar con st.connection primero
        supabase_conn = init_supabase_auth_connection()
        
        # Si falla, usar conexión directa
        if not supabase_conn:
            supabase_client = init_supabase_direct()
            if supabase_client:
                supabase_client.auth.sign_out()
        else:
            supabase_conn.client.auth.sign_out()
    except Exception as e:
        # Ignorar errores de logout, limpiar session state de todas formas
        pass
    
    # Limpiar session state
    for key in list(st.session_state.keys()):
        if key.startswith('auth_'):
            del st.session_state[key]
    
    st.session_state.authenticated = False
    st.session_state.user_data = None

def check_authentication() -> bool:
    """Verifica si el usuario está autenticado"""
    if not st.session_state.get('authenticated', False):
        return False
    
    # Verificar token si existe
    if 'auth_token' in st.session_state:
        user_data = verify_jwt_token(st.session_state.auth_token)
        if user_data is None:
            logout_user()
            return False
        
        # Actualizar datos del usuario en session state
        st.session_state.user_data = user_data
    
    return st.session_state.get('authenticated', False)

def require_authentication():
    """Decorator/helper para requerir autenticación"""
    if not check_authentication():
        show_login_page()
        st.stop()

def show_login_page():
    """Muestra la página de login/registro"""
    st.markdown("<h1 style='text-align: center; color: #4A4A4A;'>⚖️ LegalIA - Acceso al Sistema</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Inicie sesión para acceder al sistema de gestión de casos legales</p>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Tabs para Login y Registro
    tab1, tab2 = st.tabs(["🔐 Iniciar Sesión", "📝 Registrarse"])
    
    with tab1:
        st.subheader("Iniciar Sesión")
        with st.form("login_form"):
            email = st.text_input("📧 Email", key="login_email", placeholder="usuario@ejemplo.com")
            password = st.text_input("🔒 Contraseña", type="password", key="login_password", placeholder="Ingrese su contraseña")
            
            # Botón de login con estilo
            submit_login = st.form_submit_button("🚀 Iniciar Sesión", use_container_width=True, type="primary")
            
            if submit_login:
                if email and password:
                    with st.spinner("🔄 Verificando credenciales..."):
                        user_data = login_user(email, password)
                        
                        if user_data:
                            # Guardar datos en session state
                            st.session_state.authenticated = True
                            st.session_state.user_data = user_data
                            st.session_state.auth_token = user_data['token']
                            
                            role_display = get_role_display_name(user_data.get('rol', 'cliente'))
                            st.success(f"✅ ¡Bienvenido, {user_data['nombre_completo']}!\n\n{role_display}")
                            st.balloons()  # Efecto visual
                            st.rerun()
                        else:
                            st.error("❌ Email o contraseña incorrectos")
                else:
                    st.error("❌ Por favor, complete todos los campos")
    
    with tab2:
        st.subheader("Crear Cuenta Nueva")
        with st.form("register_form"):
            # Campos básicos en dos columnas
            col1, col2 = st.columns(2)
            
            with col1:
                reg_nombre = st.text_input("Nombre Completo", key="reg_nombre")
                reg_email = st.text_input("Email", key="reg_email")
                
            with col2:
                reg_password = st.text_input("Contraseña", type="password", key="reg_password")
                reg_confirm_password = st.text_input("Confirmar Contraseña", type="password", key="reg_confirm")
            
            # Selección de rol (solo visible si hay un admin logueado)
            reg_rol = "cliente"  # Por defecto
            
            # Verificar si el usuario actual es admin para permitir selección de rol
            current_user_is_admin = False
            if check_authentication() and 'user_data' in st.session_state and st.session_state.user_data:
                current_role = st.session_state.user_data.get('rol', '').lower()
                current_user_is_admin = current_role in ['administrador', 'admin']
            
            if current_user_is_admin:
                st.markdown("**🔐 Configuración de Rol (Solo Administradores)**")
                role_options = get_available_roles()
                role_labels = [get_role_display_name(role) for role in role_options]
                
                selected_role_index = st.selectbox(
                    "Seleccionar Rol",
                    range(len(role_options)),
                    format_func=lambda x: role_labels[x],
                    index=4  # Default to "cliente"
                )
                reg_rol = role_options[selected_role_index]
            else:
                st.info("💡 Las nuevas cuentas se crearán con rol de Cliente por defecto")
            
            # Botón de registro
            submit_registro = st.form_submit_button("🚀 Registrarse", use_container_width=True, type="primary")
            
            # Procesar formulario
            if submit_registro:
                if all([reg_nombre, reg_email, reg_password, reg_confirm_password]):
                    if reg_password != reg_confirm_password:
                        st.error("❌ Las contraseñas no coinciden")
                    elif len(reg_password) < 6:
                        st.error("❌ La contraseña debe tener al menos 6 caracteres")
                    else:
                        with st.spinner("🔄 Creando cuenta..."):
                            if register_user(reg_email, reg_password, reg_nombre, reg_rol):
                                success_msg = f"✅ ¡Cuenta creada exitosamente como {get_role_display_name(reg_rol)}!"
                                if not current_user_is_admin:
                                    success_msg += "\n\n📧 Revise su email para confirmar y luego inicie sesión."
                                st.success(success_msg)
                                st.balloons()  # Añadir efecto visual
                            else:
                                st.error("❌ Error al crear la cuenta. El email podría estar ya registrado.")
                else:
                    st.error("❌ Por favor, complete todos los campos")

def show_user_info():
    """Muestra información del usuario en la sidebar"""
    if check_authentication() and st.session_state.get('user_data'):
        user_data = st.session_state.user_data
        user_role = user_data.get('rol', 'cliente')
        
        st.sidebar.markdown("---")
        st.sidebar.markdown("**👤 Usuario Actual**")
        st.sidebar.markdown(f"**{user_data.get('nombre_completo', 'Usuario')}**")
        st.sidebar.markdown(f"*{user_data.get('email', '')}*")
        
        # Mostrar rol con emoji
        role_display = get_role_display_name(user_role)
        st.sidebar.markdown(f"**{role_display}**")
        
        # Mostrar permisos del rol
        with st.sidebar.expander("🔐 Permisos del Rol", expanded=False):
            permissions = get_role_permissions().get(user_role.lower(), {})
            
            st.write("**Accesos permitidos:**")
            for perm, allowed in permissions.items():
                if allowed and perm not in ['ver_todos_casos', 'editar_todos_casos', 'eliminar_casos', 'gestionar_roles']:
                    icon = "✅" if allowed else "❌"
                    perm_name = perm.replace('_', ' ').title()
                    st.write(f"{icon} {perm_name}")
        
        if st.sidebar.button("🚪 Cerrar Sesión", use_container_width=True):
            logout_user()
            st.rerun()

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

# Verificar autenticación antes de mostrar cualquier contenido
if not check_authentication():
    show_login_page()
    st.stop()

# Mostrar información del usuario en la sidebar
show_user_info()

st.sidebar.title("Menú de Navegación")
st.sidebar.markdown("Seleccione un Módulo")

# Debug temporal: mostrar rol actual
if st.session_state.get('authenticated', False):
    current_user_data = st.session_state.get('user_data', {})
    current_role = current_user_data.get('rol', 'N/A')
    st.sidebar.info(f"Debug - Rol actual: {current_role}")

# Construir lista de módulos basada en permisos del usuario
available_modules = []

# Agregar módulos según permisos
if has_permission("dashboard"):
    available_modules.append("📊 Dashboard")

if has_permission("crear_caso"):
    available_modules.append("➕ Crear Nuevo Caso")

if has_permission("gestion_documental"):
    available_modules.append("📂 Gestión Documental")

if has_permission("gestionar_usuarios"):
    available_modules.append("👥 Gestionar Clientes y Abogados")

if has_permission("reportes"):
    available_modules.append("📈 Reportes y Analytics")

if has_permission("agenda"):
    available_modules.append("📅 Agenda y Calendario")

if has_permission("notificaciones"):
    available_modules.append("🔔 Notificaciones")

if has_permission("tareas"):
    available_modules.append("📋 Tareas y Workflow")

# Mi Perfil siempre disponible para usuarios autenticados
if has_permission("mi_perfil"):
    available_modules.append("👤 Mi Perfil")

# Solo mostrar Gestión de Usuarios si es admin
# Solo mostrar Gestión de Usuarios si es admin O si es el primer usuario (bootstrap)
bootstrap_access = False
if 'user_data' in st.session_state and st.session_state.user_data:
    user_email = st.session_state.user_data.get('email', '').lower()
    # Permitir acceso al primer usuario registrado para bootstrap
    if user_email in ['noe@gmail.com', 'noelia.cq28@gmail.com']:  # Emails de bootstrap
        bootstrap_access = True

if has_permission("gestionar_roles") or bootstrap_access:
    available_modules.append("🔧 Gestión de Usuarios")

page = st.sidebar.radio("Módulos", available_modules, label_visibility="hidden")

st.sidebar.markdown("---")

# Botón de reinicio de conexión en la barra lateral
if st.sidebar.button("🔄 Reiniciar Conexión DB"):
    reset_database_connection()

# Botón de emergencia para refrescar permisos
if st.session_state.get('authenticated', False):
    if st.sidebar.button("🔄 Refrescar Permisos", help="Actualiza los permisos desde la base de datos"):
        if refresh_user_data():
            st.success("✅ Permisos actualizados!")
            st.rerun()
        else:
            st.error("❌ Error al actualizar permisos")

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
if page == "📊 Dashboard":
    st.header("📊 Dashboard de Casos")
    require_permission("dashboard")
    
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
                            


# --- Página de Creación de Casos ---
elif page == "➕ Crear Nuevo Caso":
    st.header("➕ Crear Nuevo Caso")
    require_permission("crear_caso")
    
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
elif page == "📂 Gestión Documental":
    st.header("📂 Gestión Documental")
    require_permission("gestion_documental")
    
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
elif page == "👥 Gestionar Clientes y Abogados":
    st.header("👥 Gestión de Clientes y Abogados")
    require_permission("gestionar_usuarios")
    
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

# --- Página de Gestión de Perfil ---
elif page == "👤 Mi Perfil":
    st.header("👤 Mi Perfil")
    require_permission("mi_perfil")
    
    if not check_authentication():
        st.error("Debe estar autenticado para ver esta página")
        st.stop()
    
    user_data = st.session_state.get('user_data', {})
    # Intentar obtener user_id de diferentes formas para compatibilidad
    user_id = user_data.get('id') or user_data.get('user_id')
    
    # Obtener datos actuales del perfil
    try:
        conn = init_db_connection()
        if conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM perfiles WHERE id = %s", (user_id,))
                perfil_actual = cur.fetchone()
                
                if perfil_actual:
                    # Mostrar información actual
                    st.subheader("📋 Información Actual")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.info(f"**Email:** {user_data.get('email', 'N/A')}")
                        st.info(f"**Nombre:** {perfil_actual[1] if len(perfil_actual) > 1 else 'N/A'}")
                    
                    with col2:
                        st.info(f"**Rol:** {perfil_actual[2] if len(perfil_actual) > 2 else 'N/A'}")
                        st.info(f"**ID de Usuario:** {user_id}")
                        
                        # Botón para refrescar permisos
                        if st.button("🔄 Refrescar Permisos", use_container_width=True, help="Actualiza los permisos en la sesión actual"):
                            if refresh_user_data():
                                st.success("✅ Permisos actualizados!")
                                st.rerun()
                            else:
                                st.error("❌ Error al actualizar permisos")
                    
                    st.markdown("---")
                    
                    # Formulario para actualizar perfil
                    st.subheader("✏️ Actualizar Información")
                    with st.form("update_profile_form"):
                        nuevo_nombre = st.text_input(
                            "Nombre Completo", 
                            value=perfil_actual[1] if len(perfil_actual) > 1 else "",
                            help="Actualice su nombre completo"
                        )
                        
                        # Solo mostrar cambio de rol si es admin
                        current_rol = perfil_actual[2] if len(perfil_actual) > 2 else "usuario"
                        if current_rol == "admin":
                            nuevo_rol = st.selectbox(
                                "Rol", 
                                ["usuario", "admin"],
                                index=0 if current_rol == "usuario" else 1,
                                help="Solo administradores pueden cambiar roles"
                            )
                        else:
                            st.info(f"**Rol actual:** {current_rol} (Solo administradores pueden cambiar roles)")
                            nuevo_rol = current_rol
                        
                        if st.form_submit_button("💾 Actualizar Perfil", use_container_width=True):
                            if nuevo_nombre.strip():
                                try:
                                    # Actualizar perfil en la base de datos
                                    update_query = "UPDATE perfiles SET nombre_completo = %s, rol = %s WHERE id = %s"
                                    cur.execute(update_query, (nuevo_nombre.strip(), nuevo_rol, user_id))
                                    conn.commit()
                                    
                                    # Actualizar session state
                                    st.session_state.user_data['nombre_completo'] = nuevo_nombre.strip()
                                    st.session_state.user_data['rol'] = nuevo_rol
                                    
                                    st.success("✅ Perfil actualizado exitosamente!")
                                    st.rerun()
                                    
                                except Exception as e:
                                    st.error(f"❌ Error al actualizar perfil: {e}")
                            else:
                                st.error("❌ El nombre no puede estar vacío")
                    
                    st.markdown("---")
                    
                    # Sección de cambio de contraseña
                    st.subheader("🔐 Cambiar Contraseña")
                    with st.expander("Cambiar mi contraseña", expanded=False):
                        with st.form("change_password_form"):
                            nueva_password = st.text_input("Nueva Contraseña", type="password")
                            confirmar_password = st.text_input("Confirmar Nueva Contraseña", type="password")
                            
                            if st.form_submit_button("🔄 Cambiar Contraseña"):
                                if nueva_password and confirmar_password:
                                    if nueva_password == confirmar_password:
                                        if len(nueva_password) >= 6:
                                            try:
                                                # Intentar con st.connection primero
                                                supabase_conn = init_supabase_auth_connection()
                                                
                                                # Si falla, usar conexión directa
                                                if not supabase_conn:
                                                    supabase_client = init_supabase_direct()
                                                    if not supabase_client:
                                                        st.error("❌ No se pudo conectar al sistema de autenticación")
                                                    else:
                                                        # Actualizar contraseña en Supabase Auth
                                                        supabase_client.auth.update_user({
                                                            "password": nueva_password
                                                        })
                                                        st.success("✅ Contraseña actualizada exitosamente!")
                                                else:
                                                    supabase_client = supabase_conn.client
                                                    # Actualizar contraseña en Supabase Auth
                                                    supabase_client.auth.update_user({
                                                        "password": nueva_password
                                                    })
                                                    st.success("✅ Contraseña actualizada exitosamente!")
                                            except Exception as e:
                                                st.error(f"❌ Error al cambiar contraseña: {e}")
                                        else:
                                            st.error("❌ La contraseña debe tener al menos 6 caracteres")
                                    else:
                                        st.error("❌ Las contraseñas no coinciden")
                                else:
                                    st.error("❌ Complete todos los campos")
                    
                    # Información adicional
                    st.markdown("---")
                    st.subheader("📊 Estadísticas de Uso")
                    
                    # Contar casos creados por el usuario (si aplicable)
                    try:
                        # Esta sería una mejora futura: rastrear qué usuario crea qué casos
                        st.info("🚧 Próximamente: Estadísticas detalladas de uso del sistema")
                    except Exception as e:
                        st.warning("No se pudieron cargar las estadísticas")
                        
                else:
                    st.warning("⚠️ No se encontró el perfil del usuario en la base de datos")
                    st.info("💡 Esto puede suceder si el perfil no se creó correctamente durante el registro")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("🔄 Recrear Perfil Automáticamente", use_container_width=True):
                            try:
                                # Verificar que tenemos un user_id válido usando la misma lógica que refresh_user_data
                                user_id_para_perfil = user_data.get('id') or user_data.get('user_id')
                                
                                if not user_id_para_perfil or user_id_para_perfil == "":
                                    st.error("❌ No se puede recrear el perfil: user_id es inválido")
                                    st.info("💡 Intente cerrar sesión y volver a iniciar")
                                    st.stop()
                                
                                # Primero verificar si ya existe
                                cur.execute("SELECT id, rol FROM perfiles WHERE id = %s", (user_id_para_perfil,))
                                exists = cur.fetchone()
                                
                                if exists:
                                    st.warning("⚠️ El perfil ya existe, actualizando...")
                                    # Mantener el rol existente si es administrador
                                    rol_actual = exists[1] if exists[1] in ['administrador', 'socio', 'abogado_senior', 'abogado_junior'] else 'cliente'
                                    update_query = "UPDATE perfiles SET nombre_completo = %s, rol = %s WHERE id = %s"
                                    cur.execute(update_query, (user_data.get('nombre_completo', user_data.get('email', 'Usuario')), rol_actual, user_id_para_perfil))
                                    rol_asignado = rol_actual
                                else:
                                    # Crear nuevo perfil
                                    insert_query = "INSERT INTO perfiles (id, nombre_completo, rol) VALUES (%s, %s, %s)"
                                    nombre_para_perfil = user_data.get('nombre_completo') or user_data.get('email', 'Usuario')
                                    # Dar rol admin a usuarios bootstrap
                                    user_email = user_data.get('email', '').lower()
                                    rol_asignado = 'administrador' if user_email in ['noe@gmail.com', 'noelia.cq28@gmail.com'] else 'cliente'
                                    cur.execute(insert_query, (user_id_para_perfil, nombre_para_perfil, rol_asignado))
                                
                                conn.commit()
                                
                                # Refrescar datos del usuario en session state
                                if refresh_user_data():
                                    st.success(f"✅ Perfil recreado/actualizado exitosamente! Rol asignado: {rol_asignado}")
                                    st.info("🔄 Actualizando interfaz con nuevos permisos...")
                                    # Forzar actualización completa de la página
                                    st.balloons()
                                    st.rerun()
                                else:
                                    st.warning("⚠️ Perfil creado pero hubo problemas al actualizar la sesión. Cierre sesión y vuelva a entrar.")
                                
                            except Exception as e:
                                st.error(f"❌ Error al recrear perfil: {e}")
                                st.code(f"User ID intentado: {user_id_para_perfil if 'user_id_para_perfil' in locals() else 'No definido'}")
                                st.code(f"User Data: {user_data}")
                    
                    with col2:
                        if st.button("🔍 Verificar Conexión DB", use_container_width=True):
                            if test_database_connection():
                                st.success("✅ Conexión a base de datos OK")
                            else:
                                st.error("❌ Problema de conexión a base de datos")
                    
                    # Mostrar información de debug
                    with st.expander("🔧 Información de Debug", expanded=False):
                        st.json({
                            "user_id": user_id,
                            "email": user_data.get('email', 'N/A'),
                            "session_data": dict(user_data) if user_data else "No hay datos"
                        })
    
    except Exception as e:
        st.error(f"❌ Error al cargar perfil: {e}")
        if not test_database_connection():
            st.stop()

# --- Página de Reportes y Analytics ---
elif page == "📈 Reportes y Analytics":
    st.header("📈 Reportes y Analytics")
    require_permission("reportes")
    
    st.subheader("📊 Métricas del Despacho")
    
    # Verificar conexión antes de continuar
    if not test_database_connection():
        st.stop()
    
    # Métricas generales
    col1, col2, col3, col4 = st.columns(4)
    
    try:
        # Total de casos
        total_casos = run_query("SELECT COUNT(*) as total FROM casos").iloc[0]['total']
        col1.metric("📋 Total de Casos", total_casos)
        
        # Casos activos
        casos_activos = run_query("SELECT COUNT(*) as activos FROM casos WHERE estado IN ('Abierto', 'En Progreso')").iloc[0]['activos']
        col2.metric("🔄 Casos Activos", casos_activos)
        
        # Total de clientes
        total_clientes = run_query("SELECT COUNT(*) as total FROM clientes").iloc[0]['total']
        col3.metric("👥 Total de Clientes", total_clientes)
        
        # Total de abogados
        total_abogados = run_query("SELECT COUNT(*) as total FROM abogados").iloc[0]['total']
        col4.metric("⚖️ Total de Abogados", total_abogados)
        
    except Exception as e:
        st.error(f"Error al cargar métricas: {e}")
    
    st.markdown("---")
    
    # Gráficos y reportes
    tab1, tab2, tab3 = st.tabs(["📊 Estados de Casos", "📈 Casos por Mes", "👨‍💼 Productividad"])
    
    with tab1:
        st.subheader("Distribución de Estados de Casos")
        try:
            estados_data = run_query("""
                SELECT estado, COUNT(*) as cantidad 
                FROM casos 
                GROUP BY estado 
                ORDER BY cantidad DESC
            """)
            
            if not estados_data.empty:
                st.bar_chart(estados_data.set_index('estado'))
                st.dataframe(estados_data, use_container_width=True)
            else:
                st.info("No hay datos de casos para mostrar")
        except Exception as e:
            st.error(f"Error al cargar datos de estados: {e}")
    
    with tab2:
        st.subheader("Casos Creados por Mes")
        try:
            casos_mes = run_query("""
                SELECT 
                    TO_CHAR(fecha_apertura, 'YYYY-MM') as mes,
                    COUNT(*) as casos_creados
                FROM casos 
                WHERE fecha_apertura >= CURRENT_DATE - INTERVAL '12 months'
                GROUP BY TO_CHAR(fecha_apertura, 'YYYY-MM')
                ORDER BY mes
            """)
            
            if not casos_mes.empty:
                st.line_chart(casos_mes.set_index('mes'))
                st.dataframe(casos_mes, use_container_width=True)
            else:
                st.info("No hay datos de casos recientes para mostrar")
        except Exception as e:
            st.error(f"Error al cargar datos temporales: {e}")
    
    with tab3:
        st.subheader("Casos por Abogado")
        try:
            productividad = run_query("""
                SELECT 
                    a.nombre || ' ' || a.apellido as abogado,
                    COUNT(c.id_caso) as total_casos,
                    COUNT(CASE WHEN c.estado IN ('Abierto', 'En Progreso') THEN 1 END) as casos_activos
                FROM abogados a
                LEFT JOIN casos c ON a.id_abogado = c.id_abogado
                GROUP BY a.id_abogado, a.nombre, a.apellido
                ORDER BY total_casos DESC
            """)
            
            if not productividad.empty:
                st.dataframe(productividad, use_container_width=True)
                
                # Gráfico de barras
                st.bar_chart(productividad.set_index('abogado')['total_casos'])
            else:
                st.info("No hay datos de productividad para mostrar")
        except Exception as e:
            st.error(f"Error al cargar datos de productividad: {e}")

# --- Página de Agenda y Calendario ---
elif page == "📅 Agenda y Calendario":
    st.header("📅 Agenda y Calendario")
    require_permission("agenda")
    
    st.subheader("🗓️ Gestión de Citas y Eventos")
    
    # Verificar conexión antes de continuar
    if not test_database_connection():
        st.stop()
    
    # Crear tabla de eventos si no existe
    try:
        conn = init_db_connection()
        if conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS eventos (
                        id_evento SERIAL PRIMARY KEY,
                        titulo VARCHAR(200) NOT NULL,
                        descripcion TEXT,
                        fecha_evento DATE NOT NULL,
                        hora_inicio TIME,
                        hora_fin TIME,
                        id_caso INTEGER REFERENCES casos(id_caso),
                        id_abogado INTEGER REFERENCES abogados(id_abogado),
                        tipo_evento VARCHAR(50) DEFAULT 'cita',
                        estado VARCHAR(50) DEFAULT 'programado',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                conn.commit()
    except Exception as e:
        st.warning(f"Advertencia al crear tabla de eventos: {e}")
    
    # Pestañas para diferentes vistas
    tab1, tab2, tab3 = st.tabs(["📅 Ver Calendario", "➕ Nueva Cita", "📋 Próximos Eventos"])
    
    with tab1:
        st.subheader("Vista de Calendario")
        
        # Selector de fecha
        fecha_seleccionada = st.date_input("Seleccionar fecha", datetime.now().date())
        
        # Mostrar eventos del día
        try:
            eventos_dia = run_query("""
                SELECT e.*, c.titulo as caso_titulo, a.nombre || ' ' || a.apellido as abogado_nombre
                FROM eventos e
                LEFT JOIN casos c ON e.id_caso = c.id_caso
                LEFT JOIN abogados a ON e.id_abogado = a.id_abogado
                WHERE e.fecha_evento = %s
                ORDER BY e.hora_inicio
            """, (fecha_seleccionada,))
            
            if not eventos_dia.empty:
                st.success(f"📅 Eventos para {fecha_seleccionada.strftime('%d/%m/%Y')}")
                for idx, evento in eventos_dia.iterrows():
                    with st.expander(f"🕐 {evento['hora_inicio']} - {evento['titulo']}"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Descripción:** {evento['descripcion']}")
                            st.write(f"**Tipo:** {evento['tipo_evento']}")
                            st.write(f"**Estado:** {evento['estado']}")
                        with col2:
                            if evento['caso_titulo']:
                                st.write(f"**Caso:** {evento['caso_titulo']}")
                            if evento['abogado_nombre']:
                                st.write(f"**Abogado:** {evento['abogado_nombre']}")
                            st.write(f"**Horario:** {evento['hora_inicio']} - {evento['hora_fin']}")
            else:
                st.info(f"No hay eventos programados para {fecha_seleccionada.strftime('%d/%m/%Y')}")
                
        except Exception as e:
            st.error(f"Error al cargar eventos: {e}")
    
    with tab2:
        st.subheader("Programar Nueva Cita")
        
        with st.form("nueva_cita_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                titulo_evento = st.text_input("Título del Evento")
                descripcion_evento = st.text_area("Descripción")
                fecha_evento = st.date_input("Fecha", datetime.now().date())
                
            with col2:
                hora_inicio = st.time_input("Hora de Inicio", datetime.now().time())
                hora_fin = st.time_input("Hora de Fin", (datetime.now() + timedelta(hours=1)).time())
                tipo_evento = st.selectbox("Tipo de Evento", 
                    ["cita", "audiencia", "reunion", "deadline", "otro"])
            
            # Selección opcional de caso y abogado
            casos = get_cases_detailed()
            abogados = get_lawyers()
            
            caso_seleccionado = None
            if not casos.empty:
                caso_opciones = ["Ninguno"] + casos['titulo'].tolist()
                caso_idx = st.selectbox("Caso Relacionado (Opcional)", range(len(caso_opciones)), 
                    format_func=lambda x: caso_opciones[x])
                if caso_idx > 0:
                    caso_seleccionado = casos.iloc[caso_idx-1]['id_caso']
            
            abogado_seleccionado = None
            if not abogados.empty:
                abogado_opciones = ["Ninguno"] + abogados['nombre_completo'].tolist()
                abogado_idx = st.selectbox("Abogado Asignado (Opcional)", range(len(abogado_opciones)),
                    format_func=lambda x: abogado_opciones[x])
                if abogado_idx > 0:
                    abogado_seleccionado = abogados.iloc[abogado_idx-1]['id_abogado']
            
            if st.form_submit_button("📅 Programar Evento", use_container_width=True):
                if titulo_evento and fecha_evento:
                    try:
                        conn = init_db_connection()
                        if conn:
                            with conn.cursor() as cur:
                                cur.execute("""
                                    INSERT INTO eventos (titulo, descripcion, fecha_evento, hora_inicio, hora_fin, 
                                                       id_caso, id_abogado, tipo_evento)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                """, (titulo_evento, descripcion_evento, fecha_evento, hora_inicio, 
                                     hora_fin, caso_seleccionado, abogado_seleccionado, tipo_evento))
                                conn.commit()
                                st.success("✅ Evento programado exitosamente!")
                                st.rerun()
                    except Exception as e:
                        st.error(f"Error al programar evento: {e}")
                else:
                    st.error("El título y la fecha son obligatorios")
    
    with tab3:
        st.subheader("Próximos Eventos")
        
        try:
            proximos_eventos = run_query("""
                SELECT e.*, c.titulo as caso_titulo, a.nombre || ' ' || a.apellido as abogado_nombre
                FROM eventos e
                LEFT JOIN casos c ON e.id_caso = c.id_caso
                LEFT JOIN abogados a ON e.id_abogado = a.id_abogado
                WHERE e.fecha_evento >= CURRENT_DATE
                ORDER BY e.fecha_evento, e.hora_inicio
                LIMIT 20
            """)
            
            if not proximos_eventos.empty:
                st.dataframe(proximos_eventos[['titulo', 'fecha_evento', 'hora_inicio', 'tipo_evento', 'caso_titulo', 'abogado_nombre']], 
                           use_container_width=True)
            else:
                st.info("No hay eventos próximos programados")
                
        except Exception as e:
            st.error(f"Error al cargar próximos eventos: {e}")

# --- Página de Notificaciones ---
elif page == "🔔 Notificaciones":
    st.header("🔔 Notificaciones y Alertas")
    require_permission("notificaciones")
    
    st.subheader("📬 Centro de Notificaciones")
    
    # Crear tabla de notificaciones si no existe
    try:
        conn = init_db_connection()
        if conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS notificaciones (
                        id_notificacion SERIAL PRIMARY KEY,
                        titulo VARCHAR(200) NOT NULL,
                        mensaje TEXT NOT NULL,
                        tipo VARCHAR(50) DEFAULT 'info',
                        usuario_id UUID,
                        leida BOOLEAN DEFAULT FALSE,
                        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        fecha_expiracion DATE
                    );
                """)
                conn.commit()
    except Exception as e:
        st.warning(f"Advertencia al crear tabla de notificaciones: {e}")
    
    # Tabs para diferentes tipos de notificaciones
    tab1, tab2, tab3 = st.tabs(["📥 Mis Notificaciones", "⚠️ Alertas del Sistema", "🔔 Configuración"])
    
    with tab1:
        st.subheader("Notificaciones Personales")
        
        try:
            user_id = st.session_state.get('user_data', {}).get('id')
            
            notificaciones = run_query("""
                SELECT * FROM notificaciones 
                WHERE usuario_id = %s OR usuario_id IS NULL
                ORDER BY fecha_creacion DESC
                LIMIT 50
            """, (user_id,))
            
            if not notificaciones.empty:
                for idx, notif in notificaciones.iterrows():
                    # Icono según tipo
                    icon = {"info": "ℹ️", "warning": "⚠️", "error": "❌", "success": "✅"}.get(notif['tipo'], "📝")
                    leida_icon = "👁️" if notif['leida'] else "🔵"
                    
                    with st.expander(f"{icon} {leida_icon} {notif['titulo']} - {notif['fecha_creacion'].strftime('%d/%m/%Y %H:%M')}"):
                        st.write(notif['mensaje'])
                        
                        col1, col2 = st.columns([1, 1])
                        with col1:
                            if not notif['leida']:
                                if st.button("✅ Marcar como leída", key=f"read_{notif['id_notificacion']}"):
                                    try:
                                        conn = init_db_connection()
                                        if conn:
                                            with conn.cursor() as cur:
                                                cur.execute("UPDATE notificaciones SET leida = TRUE WHERE id_notificacion = %s", 
                                                          (notif['id_notificacion'],))
                                                conn.commit()
                                                st.rerun()
                                    except Exception as e:
                                        st.error(f"Error al actualizar notificación: {e}")
                        
                        with col2:
                            if st.button("🗑️ Eliminar", key=f"del_{notif['id_notificacion']}"):
                                try:
                                    conn = init_db_connection()
                                    if conn:
                                        with conn.cursor() as cur:
                                            cur.execute("DELETE FROM notificaciones WHERE id_notificacion = %s", 
                                                      (notif['id_notificacion'],))
                                            conn.commit()
                                            st.rerun()
                                except Exception as e:
                                    st.error(f"Error al eliminar notificación: {e}")
            else:
                st.info("No tienes notificaciones pendientes")
                
        except Exception as e:
            st.error(f"Error al cargar notificaciones: {e}")
    
    with tab2:
        st.subheader("Alertas Automáticas del Sistema")
        
        # Alertas de casos próximos a vencer
        st.markdown("**🚨 Casos que requieren atención:**")
        
        try:
            # Casos sin actividad reciente
            casos_inactivos = run_query("""
                SELECT c.titulo, c.estado, c.fecha_apertura,
                       cl.nombre || ' ' || cl.apellido as cliente,
                       a.nombre || ' ' || a.apellido as abogado
                FROM casos c
                JOIN clientes cl ON c.id_cliente = cl.id_cliente
                JOIN abogados a ON c.id_abogado = a.id_abogado
                WHERE c.estado IN ('Abierto', 'En Progreso')
                AND c.fecha_apertura < CURRENT_DATE - INTERVAL '30 days'
                ORDER BY c.fecha_apertura
            """)
            
            if not casos_inactivos.empty:
                st.warning(f"⚠️ {len(casos_inactivos)} casos sin actividad reciente (más de 30 días)")
                st.dataframe(casos_inactivos, use_container_width=True)
            else:
                st.success("✅ Todos los casos están al día")
                
            # Eventos próximos
            eventos_proximos = run_query("""
                SELECT titulo, fecha_evento, hora_inicio, tipo_evento
                FROM eventos 
                WHERE fecha_evento BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '7 days'
                AND estado = 'programado'
                ORDER BY fecha_evento, hora_inicio
            """)
            
            if not eventos_proximos.empty:
                st.info(f"📅 {len(eventos_proximos)} eventos próximos (próximos 7 días)")
                st.dataframe(eventos_proximos, use_container_width=True)
                
        except Exception as e:
            st.error(f"Error al cargar alertas: {e}")
    
    with tab3:
        st.subheader("Configuración de Notificaciones")
        
        st.markdown("**🔔 Preferencias de Notificaciones**")
        
        # Simulación de configuraciones (se pueden guardar en la BD)
        notif_casos_nuevos = st.checkbox("Notificar cuando se creen nuevos casos", value=True)
        notif_documentos = st.checkbox("Notificar cuando se suban nuevos documentos", value=True)
        notif_eventos = st.checkbox("Recordatorios de eventos (24h antes)", value=True)
        notif_casos_inactivos = st.checkbox("Alertas de casos inactivos (30+ días)", value=True)
        
        if st.button("💾 Guardar Configuración"):
            st.success("✅ Configuración guardada exitosamente!")

# --- Página de Tareas y Workflow ---
elif page == "📋 Tareas y Workflow":
    st.header("📋 Tareas y Workflow")
    require_permission("tareas")
    
    st.subheader("✅ Gestión de Tareas y Flujos de Trabajo")
    
    # Crear tabla de tareas si no existe
    try:
        conn = init_db_connection()
        if conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS tareas (
                        id_tarea SERIAL PRIMARY KEY,
                        titulo VARCHAR(200) NOT NULL,
                        descripcion TEXT,
                        prioridad VARCHAR(20) DEFAULT 'media',
                        estado VARCHAR(50) DEFAULT 'pendiente',
                        fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        fecha_vencimiento DATE,
                        id_caso INTEGER REFERENCES casos(id_caso),
                        id_abogado INTEGER REFERENCES abogados(id_abogado),
                        creado_por UUID,
                        asignado_a UUID,
                        tiempo_estimado INTEGER, -- en horas
                        tiempo_real INTEGER -- en horas
                    );
                """)
                conn.commit()
    except Exception as e:
        st.warning(f"Advertencia al crear tabla de tareas: {e}")
    
    # Tabs para diferentes vistas
    tab1, tab2, tab3, tab4 = st.tabs(["📋 Mis Tareas", "➕ Nueva Tarea", "📊 Dashboard de Tareas", "⚡ Workflows"])
    
    with tab1:
        st.subheader("Mis Tareas Asignadas")
        
        user_id = st.session_state.get('user_data', {}).get('id')
        
        # Filtros
        col1, col2, col3 = st.columns(3)
        with col1:
            filtro_estado = st.selectbox("Estado", ["Todas", "pendiente", "en_progreso", "completada", "cancelada"])
        with col2:
            filtro_prioridad = st.selectbox("Prioridad", ["Todas", "alta", "media", "baja"])
        with col3:
            solo_vencidas = st.checkbox("Solo tareas vencidas")
        
        try:
            query = """
                SELECT t.*, c.titulo as caso_titulo, a.nombre || ' ' || a.apellido as abogado_nombre
                FROM tareas t
                LEFT JOIN casos c ON t.id_caso = c.id_caso
                LEFT JOIN abogados a ON t.id_abogado = a.id_abogado
                WHERE t.asignado_a = %s OR t.creado_por = %s
            """
            params = [user_id, user_id]
            
            if filtro_estado != "Todas":
                query += " AND t.estado = %s"
                params.append(filtro_estado)
                
            if filtro_prioridad != "Todas":
                query += " AND t.prioridad = %s"
                params.append(filtro_prioridad)
                
            if solo_vencidas:
                query += " AND t.fecha_vencimiento < CURRENT_DATE AND t.estado != 'completada'"
            
            query += " ORDER BY t.fecha_vencimiento, t.prioridad DESC"
            
            tareas = run_query(query, params)
            
            if not tareas.empty:
                for idx, tarea in tareas.iterrows():
                    # Colores según prioridad y estado
                    prioridad_color = {"alta": "🔴", "media": "🟡", "baja": "🟢"}.get(tarea['prioridad'], "⚪")
                    estado_icon = {"pendiente": "⏳", "en_progreso": "🔄", "completada": "✅", "cancelada": "❌"}.get(tarea['estado'], "📝")
                    
                    # Verificar si está vencida
                    vencida = ""
                    if tarea['fecha_vencimiento'] and tarea['fecha_vencimiento'] < datetime.now().date() and tarea['estado'] != 'completada':
                        vencida = "🚨 VENCIDA - "
                    
                    with st.expander(f"{prioridad_color} {estado_icon} {vencida}{tarea['titulo']} - Vence: {tarea['fecha_vencimiento']}"):
                        col1, col2 = st.columns([2, 1])
                        
                        with col1:
                            st.write(f"**Descripción:** {tarea['descripcion']}")
                            if tarea['caso_titulo']:
                                st.write(f"**Caso:** {tarea['caso_titulo']}")
                            if tarea['abogado_nombre']:
                                st.write(f"**Abogado:** {tarea['abogado_nombre']}")
                            
                        with col2:
                            nuevo_estado = st.selectbox("Cambiar Estado", 
                                ["pendiente", "en_progreso", "completada", "cancelada"],
                                index=["pendiente", "en_progreso", "completada", "cancelada"].index(tarea['estado']),
                                key=f"estado_{tarea['id_tarea']}")
                            
                            if st.button("💾 Actualizar", key=f"update_{tarea['id_tarea']}"):
                                try:
                                    conn = init_db_connection()
                                    if conn:
                                        with conn.cursor() as cur:
                                            cur.execute("UPDATE tareas SET estado = %s WHERE id_tarea = %s", 
                                                      (nuevo_estado, tarea['id_tarea']))
                                            conn.commit()
                                            st.success("✅ Tarea actualizada!")
                                            st.rerun()
                                except Exception as e:
                                    st.error(f"Error al actualizar tarea: {e}")
                                    
            else:
                st.info("No tienes tareas asignadas")
                
        except Exception as e:
            st.error(f"Error al cargar tareas: {e}")
    
    with tab2:
        st.subheader("Crear Nueva Tarea")
        
        with st.form("nueva_tarea_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                titulo_tarea = st.text_input("Título de la Tarea")
                descripcion_tarea = st.text_area("Descripción Detallada")
                prioridad = st.selectbox("Prioridad", ["baja", "media", "alta"])
                fecha_vencimiento = st.date_input("Fecha de Vencimiento")
                
            with col2:
                tiempo_estimado = st.number_input("Tiempo Estimado (horas)", min_value=0.5, max_value=100.0, value=1.0, step=0.5)
                
                # Asignar a abogado (si tienes permisos)
                abogados = get_lawyers()
                abogado_asignado = None
                if not abogados.empty and has_permission("gestionar_usuarios"):
                    abogado_opciones = ["Auto-asignada"] + abogados['nombre_completo'].tolist()
                    abogado_idx = st.selectbox("Asignar a Abogado", range(len(abogado_opciones)),
                        format_func=lambda x: abogado_opciones[x])
                    if abogado_idx > 0:
                        abogado_asignado = abogados.iloc[abogado_idx-1]['id_abogado']
                
                # Caso relacionado
                casos = get_cases_detailed()
                caso_relacionado = None
                if not casos.empty:
                    caso_opciones = ["Ninguno"] + casos['titulo'].tolist()
                    caso_idx = st.selectbox("Caso Relacionado", range(len(caso_opciones)),
                        format_func=lambda x: caso_opciones[x])
                    if caso_idx > 0:
                        caso_relacionado = casos.iloc[caso_idx-1]['id_caso']
            
            if st.form_submit_button("📋 Crear Tarea", use_container_width=True):
                if titulo_tarea and fecha_vencimiento:
                    try:
                        user_id = st.session_state.get('user_data', {}).get('id')
                        asignado_a = user_id if not abogado_asignado else abogado_asignado
                        
                        conn = init_db_connection()
                        if conn:
                            with conn.cursor() as cur:
                                cur.execute("""
                                    INSERT INTO tareas (titulo, descripcion, prioridad, fecha_vencimiento, 
                                                      id_caso, id_abogado, creado_por, asignado_a, tiempo_estimado)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                                """, (titulo_tarea, descripcion_tarea, prioridad, fecha_vencimiento,
                                     caso_relacionado, abogado_asignado, user_id, asignado_a, tiempo_estimado))
                                conn.commit()
                                st.success("✅ Tarea creada exitosamente!")
                                st.rerun()
                    except Exception as e:
                        st.error(f"Error al crear tarea: {e}")
                else:
                    st.error("El título y la fecha de vencimiento son obligatorios")
    
    with tab3:
        st.subheader("Dashboard de Tareas")
        
        # Métricas de tareas
        col1, col2, col3, col4 = st.columns(4)
        
        try:
            total_tareas = run_query("SELECT COUNT(*) as total FROM tareas").iloc[0]['total']
            col1.metric("📋 Total de Tareas", total_tareas)
            
            tareas_pendientes = run_query("SELECT COUNT(*) as pendientes FROM tareas WHERE estado = 'pendiente'").iloc[0]['pendientes']
            col2.metric("⏳ Pendientes", tareas_pendientes)
            
            tareas_progreso = run_query("SELECT COUNT(*) as progreso FROM tareas WHERE estado = 'en_progreso'").iloc[0]['progreso']
            col3.metric("🔄 En Progreso", tareas_progreso)
            
            tareas_vencidas = run_query("""
                SELECT COUNT(*) as vencidas FROM tareas 
                WHERE fecha_vencimiento < CURRENT_DATE AND estado != 'completada'
            """).iloc[0]['vencidas']
            col4.metric("🚨 Vencidas", tareas_vencidas, delta_color="inverse")
            
        except Exception as e:
            st.error(f"Error al cargar métricas de tareas: {e}")
        
        # Gráfico de distribución de tareas
        try:
            distribucion = run_query("""
                SELECT estado, COUNT(*) as cantidad
                FROM tareas
                GROUP BY estado
                ORDER BY cantidad DESC
            """)
            
            if not distribucion.empty:
                st.subheader("📊 Distribución de Tareas por Estado")
                st.bar_chart(distribucion.set_index('estado'))
                
        except Exception as e:
            st.error(f"Error al cargar distribución: {e}")
    
    with tab4:
        st.subheader("Workflows Automatizados")
        
        st.info("🚧 Esta sección está en desarrollo")
        
        st.markdown("""
        **Workflows planificados:**
        
        - 🔄 **Workflow de Nuevo Caso**: Crear tareas automáticas al crear un caso
        - 📄 **Workflow de Documentos**: Asignar revisión automática de documentos
        - ⏰ **Workflow de Recordatorios**: Crear tareas de seguimiento automáticamente
        - 📊 **Workflow de Reportes**: Generar reportes periódicos automáticamente
        """)

# --- Página de Gestión de Usuarios (Solo Administradores) ---
elif page == "🔧 Gestión de Usuarios":
    st.header("🔧 Gestión de Usuarios")
    
    # Verificar permisos o acceso bootstrap
    user_email = st.session_state.get('user_data', {}).get('email', '').lower()
    bootstrap_access = user_email in ['noe@gmail.com', 'noelia.cq28@gmail.com']
    
    if not (has_permission("gestionar_roles") or bootstrap_access):
        st.error("🚫 No tienes permisos para acceder a esta funcionalidad")
        st.stop()
    
    if bootstrap_access and not has_permission("gestionar_roles"):
        st.warning("⚠️ Acceso especial de bootstrap detectado. Conviértete en administrador para acceso completo.")
    
    st.subheader("👥 Administración de Usuarios y Roles")
    
    # Verificar conexión antes de continuar
    if not test_database_connection():
        st.stop()
    
    tab1, tab2, tab3 = st.tabs(["👥 Lista de Usuarios", "➕ Crear Usuario", "🔧 Herramientas Admin"])
    
    with tab1:
        st.subheader("Usuarios Registrados")
        
        try:
            usuarios = run_query("""
                SELECT p.id, p.nombre_completo, p.rol, 
                       COUNT(c.id_caso) as casos_asignados
                FROM perfiles p
                LEFT JOIN abogados a ON LOWER(p.nombre_completo) = LOWER(a.nombre || ' ' || a.apellido)
                LEFT JOIN casos c ON a.id_abogado = c.id_abogado
                GROUP BY p.id, p.nombre_completo, p.rol
                ORDER BY p.nombre_completo
            """)
            
            if not usuarios.empty:
                for idx, usuario in usuarios.iterrows():
                    with st.expander(f"{get_role_display_name(usuario['rol'])} - {usuario['nombre_completo']}"):
                        col1, col2 = st.columns([2, 1])
                        
                        with col1:
                            st.write(f"**ID:** {usuario['id']}")
                            st.write(f"**Casos Asignados:** {usuario['casos_asignados']}")
                            
                            # Cambiar rol
                            nuevo_rol = st.selectbox(
                                "Cambiar Rol",
                                get_available_roles(),
                                index=get_available_roles().index(usuario['rol']) if usuario['rol'] in get_available_roles() else 0,
                                key=f"rol_{usuario['id']}"
                            )
                            
                        with col2:
                            if st.button("💾 Actualizar Rol", key=f"update_rol_{usuario['id']}"):
                                try:
                                    conn = init_db_connection()
                                    if conn:
                                        with conn.cursor() as cur:
                                            cur.execute("UPDATE perfiles SET rol = %s WHERE id = %s", 
                                                      (nuevo_rol, usuario['id']))
                                            conn.commit()
                                            
                                            # Si el usuario actualizado es el usuario actual, refrescar session state
                                            current_user_id = st.session_state.get('user_data', {}).get('id')
                                            if current_user_id == usuario['id']:
                                                refresh_user_data()
                                            
                                            st.success(f"✅ Rol actualizado a {get_role_display_name(nuevo_rol)}")
                                            st.rerun()
                                except Exception as e:
                                    st.error(f"Error al actualizar rol: {e}")
                            
                            if st.button("🗑️ Eliminar Usuario", key=f"delete_{usuario['id']}", type="secondary"):
                                st.warning("⚠️ Esta acción eliminará permanentemente al usuario")
                                
            else:
                st.info("No hay usuarios registrados")
                
        except Exception as e:
            st.error(f"Error al cargar usuarios: {e}")
    
    with tab2:
        st.subheader("Registro de Usuario por Administrador")
        st.info("💡 Como administrador, puedes crear usuarios con cualquier rol")
        
        # Aquí se mostrará el formulario de registro con todas las opciones de rol
        
    with tab3:
        st.subheader("🔧 Herramientas de Administración")
        
        # Botón para convertir usuarios existentes en admin
        st.markdown("**⚡ Herramientas de Emergencia**")
        st.warning("⚠️ Usar solo en caso de emergencia o configuración inicial")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🚨 Convertir Usuario en Administrador**")
            st.info("Si no hay administradores, puedes convertir un usuario existente")
            
            try:
                # Obtener lista de usuarios
                usuarios_para_admin = run_query("SELECT id, nombre_completo, rol FROM perfiles WHERE rol != 'administrador'")
                
                if not usuarios_para_admin.empty:
                    usuario_seleccionado = st.selectbox(
                        "Seleccionar usuario para convertir en admin:",
                        range(len(usuarios_para_admin)),
                        format_func=lambda x: f"{usuarios_para_admin.iloc[x]['nombre_completo']} ({usuarios_para_admin.iloc[x]['rol']})"
                    )
                    
                    if st.button("🔧 Convertir en Administrador", type="primary"):
                        try:
                            usuario_id = usuarios_para_admin.iloc[usuario_seleccionado]['id']
                            conn = init_db_connection()
                            if conn:
                                with conn.cursor() as cur:
                                    cur.execute("UPDATE perfiles SET rol = 'administrador' WHERE id = %s", (usuario_id,))
                                    conn.commit()
                                    st.success("✅ Usuario convertido en administrador exitosamente!")
                                    st.balloons()
                                    st.rerun()
                        except Exception as e:
                            st.error(f"Error al convertir usuario: {e}")
                else:
                    st.warning("No hay usuarios no-admin para convertir")
                    
            except Exception as e:
                st.error(f"Error al cargar usuarios: {e}")
        
        with col2:
            st.markdown("**📊 Estadísticas del Sistema**")
            
            try:
                # Contar usuarios por rol
                stats = run_query("""
                    SELECT rol, COUNT(*) as cantidad 
                    FROM perfiles 
                    GROUP BY rol 
                    ORDER BY cantidad DESC
                """)
                
                if not stats.empty:
                    st.dataframe(stats, use_container_width=True)
                else:
                    st.info("No hay estadísticas disponibles")
                    
            except Exception as e:
                st.error(f"Error al cargar estadísticas: {e}")
        
        # Herramienta para normalizar roles
        st.markdown("---")
        st.markdown("**🔄 Normalizar Roles del Sistema**")
        st.info("Convierte roles antiguos ('usuario') a roles válidos del sistema")
        
        if st.button("🔄 Normalizar Todos los Roles", type="secondary"):
            try:
                conn = init_db_connection()
                if conn:
                    with conn.cursor() as cur:
                        # Actualizar 'usuario' a 'cliente'
                        cur.execute("UPDATE perfiles SET rol = 'cliente' WHERE rol = 'usuario'")
                        rows_updated = cur.rowcount
                        conn.commit()
                        
                        if rows_updated > 0:
                            st.success(f"✅ Se normalizaron {rows_updated} usuarios del rol 'usuario' a 'cliente'")
                        else:
                            st.info("ℹ️ No se encontraron roles para normalizar")
                        st.rerun()
            except Exception as e:
                st.error(f"Error al normalizar roles: {e}")
        
        # Herramienta para sincronizar rol actual
        st.markdown("---")
        st.markdown("**🔄 Sincronizar Mi Rol Actual**")
        st.info("Actualiza tu rol en la sesión actual desde la base de datos")
        
        col_sync1, col_sync2 = st.columns(2)
        with col_sync1:
            if st.button("🔄 Refrescar Mi Rol", type="primary"):
                if refresh_user_data():
                    st.success("✅ Rol actualizado exitosamente!")
                    st.rerun()
                else:
                    st.error("❌ No se pudo actualizar el rol")
        
        with col_sync2:
            # Mostrar rol actual vs rol en BD
            try:
                current_user_id = st.session_state.get('user_data', {}).get('id')
                session_role = st.session_state.get('user_data', {}).get('rol', 'N/A')
                
                conn = init_db_connection()
                if conn and current_user_id:
                    with conn.cursor() as cur:
                        cur.execute("SELECT rol FROM perfiles WHERE id = %s", (current_user_id,))
                        db_role = cur.fetchone()
                        db_role = db_role[0] if db_role else 'N/A'
                        
                        st.info(f"**Sesión:** {session_role}")
                        st.info(f"**Base de Datos:** {db_role}")
                        
                        if session_role != db_role:
                            st.warning("⚠️ Los roles no coinciden - presiona 'Refrescar Mi Rol'")
            except Exception as e:
                st.warning(f"No se pudo verificar sincronización: {e}")
        
        # Herramientas para migrar datos de tablas existentes
        st.markdown("---")
        st.markdown("**📊 Migración de Datos Existentes**")
        
        col_migrar1, col_migrar2 = st.columns(2)
        
        with col_migrar1:
            st.markdown("**👥 Tabla Clientes**")
            try:
                clientes_data = run_query("SELECT * FROM clientes LIMIT 5")
                if not clientes_data.empty:
                    st.dataframe(clientes_data, use_container_width=True)
                    total_clientes = run_query("SELECT COUNT(*) as total FROM clientes").iloc[0]['total']
                    st.info(f"Total de clientes: {total_clientes}")
                    
                    if st.button("🔄 Crear Perfiles desde Clientes", type="secondary"):
                        migrar_clientes_a_perfiles()
                else:
                    st.info("No hay datos en la tabla clientes")
            except Exception as e:
                st.warning(f"Error al acceder tabla clientes: {e}")
        
        with col_migrar2:
            st.markdown("**⚖️ Tabla Abogados**")
            try:
                abogados_data = run_query("SELECT * FROM abogados LIMIT 5")
                if not abogados_data.empty:
                    st.dataframe(abogados_data, use_container_width=True)
                    total_abogados = run_query("SELECT COUNT(*) as total FROM abogados").iloc[0]['total']
                    st.info(f"Total de abogados: {total_abogados}")
                    
                    if st.button("🔄 Crear Perfiles desde Abogados", type="secondary"):
                        migrar_abogados_a_perfiles()
                else:
                    st.info("No hay datos en la tabla abogados")
            except Exception as e:
                st.warning(f"Error al acceder tabla abogados: {e}")