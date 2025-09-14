# Script de Inicialización - Sistema de Autenticación LegalIA
# Este script ayuda a verificar y configurar la autenticación

import streamlit as st
import psycopg2
from supabase import create_client

def verificar_configuracion():
    """Verifica que toda la configuración esté correcta"""
    
    st.markdown("# 🔧 Verificación de Configuración de Autenticación")
    st.markdown("---")
    
    # Verificar secrets
    st.subheader("1. 📋 Verificación de Secrets")
    
    try:
        # Verificar configuración de base de datos
        db_config = st.secrets["database"]
        st.success("✅ Configuración de base de datos encontrada")
        st.json({
            "host": db_config["host"],
            "port": db_config["port"],
            "dbname": db_config["dbname"],
            "user": db_config["user"]
        })
    except Exception as e:
        st.error(f"❌ Error en configuración de base de datos: {e}")
    
    try:
        # Verificar configuración de Supabase para autenticación
        supabase_config = st.secrets["connections"]["supabase"]
        st.success("✅ Configuración de Supabase Auth encontrada")
        
        # Verificar que sea la anon key (no service role)
        key_info = supabase_config["key"]
        if "anon" in key_info:
            st.success("✅ Usando Anon Key (correcto para autenticación)")
        elif "service_role" in key_info:
            st.warning("⚠️ Usando Service Role Key - debería ser Anon Key para autenticación")
        
        st.json({
            "url": supabase_config["url"],
            "key": supabase_config["key"][:20] + "..." if len(supabase_config["key"]) > 20 else supabase_config["key"]
        })
    except Exception as e:
        st.error(f"❌ Error en configuración de Supabase Auth: {e}")
        st.markdown("""
        **Solución**: Agregue la sección `[connections.supabase]` a sus secrets:
        ```toml
        [connections.supabase]
        url = "https://gxezyjgbghfwjhdjaegz.supabase.co"
        key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imd4ZXp5amdiZ2hmd2poZGphZWd6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTcyOTc4NzIsImV4cCI6MjA3Mjg3Mzg3Mn0.GVAY_lRRleQ2e0WnHk5EPZ7nVLosYgyKh_43VCGg_Mg"
        ```
        **IMPORTANTE**: Use el Anon Key para autenticación, no el Service Role Key
        """)
    
    # Verificar conexión a base de datos
    st.subheader("2. 🗄️ Verificación de Base de Datos")
    
    try:
        connection = psycopg2.connect(
            host=st.secrets["database"]["host"],
            port=st.secrets["database"]["port"],
            dbname=st.secrets["database"]["dbname"],
            user=st.secrets["database"]["user"],
            password=st.secrets["database"]["password"]
        )
        
        with connection.cursor() as cur:
            # Verificar que existe la tabla perfiles
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'perfiles'
                );
            """)
            
            existe_perfiles = cur.fetchone()[0]
            
            if existe_perfiles:
                st.success("✅ Tabla 'perfiles' existe")
                
                # Mostrar estructura de la tabla
                cur.execute("""
                    SELECT column_name, data_type, is_nullable
                    FROM information_schema.columns
                    WHERE table_name = 'perfiles'
                    ORDER BY ordinal_position;
                """)
                
                columns = cur.fetchall()
                st.dataframe(columns, columns=["Columna", "Tipo", "Nullable"])
                
            else:
                st.error("❌ Tabla 'perfiles' no existe")
                st.markdown("""
                **Solución**: Ejecute el siguiente SQL en su base de datos:
                ```sql
                CREATE TABLE IF NOT EXISTS perfiles (
                    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
                    nombre_completo TEXT,
                    rol VARCHAR(50) DEFAULT 'usuario'
                );
                ```
                """)
        
        connection.close()
        
    except Exception as e:
        st.error(f"❌ Error de conexión a base de datos: {e}")
    
    # Verificar conexión a Supabase
    st.subheader("3. 🚀 Verificación de Supabase Auth")
    
    try:
        supabase_url = st.secrets["connections"]["supabase"]["url"]
        supabase_key = st.secrets["connections"]["supabase"]["key"]
        
        # Probar conexión directa con supabase-py
        supabase = create_client(supabase_url, supabase_key)
        
        # Intentar una operación simple en la tabla perfiles
        response = supabase.table("perfiles").select("*").limit(1).execute()
        
        st.success("✅ Conexión a Supabase exitosa")
        st.info(f"Se pueden leer registros de la tabla perfiles: {len(response.data)} encontrados")
        
        # Probar conexión con st_supabase_connection
        try:
            from st_supabase_connection import SupabaseConnection
            supabase_conn = st.connection(
                "supabase_test",
                type=SupabaseConnection,
                url=supabase_url,
                key=supabase_key
            )
            
            # Probar que funcione la conexión
            test_response = supabase_conn.client.table("perfiles").select("*").limit(1).execute()
            st.success("✅ st.connection con Supabase funciona correctamente")
            
        except Exception as conn_error:
            st.warning(f"⚠️ st.connection tiene problemas: {conn_error}")
            st.markdown("**Nota**: La autenticación podría seguir funcionando con conexión directa")
        
    except Exception as e:
        st.error(f"❌ Error de conexión a Supabase: {e}")
        st.markdown("""
        **Posibles soluciones**:
        1. Verificar que la URL y key sean correctas
        2. Verificar que esté usando el Anon Key para autenticación
        3. Verificar políticas RLS en Supabase
        4. Comprobar que Supabase Auth esté habilitado
        """)
    
    # Verificar dependencias
    st.subheader("4. 📦 Verificación de Dependencias")
    
    dependencias = [
        "streamlit",
        "psycopg2",
        "supabase",
        "st_supabase_connection", 
        "bcrypt",
        "PyJWT"
    ]
    
    for dep in dependencias:
        try:
            __import__(dep)
            st.success(f"✅ {dep}")
        except ImportError:
            st.error(f"❌ {dep} - No instalado")
            st.code(f"pip install {dep}")
    
    st.markdown("---")
    st.markdown("### 🎉 ¡Configuración completa!")
    st.markdown("Si todos los elementos muestran ✅, el sistema de autenticación está listo para usar.")

if __name__ == "__main__":
    verificar_configuracion()