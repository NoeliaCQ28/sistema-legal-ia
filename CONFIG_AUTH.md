# Configuración de Autenticación LegalIA - Streamlit.io

## ⚠️ IMPORTANTE: Configuración de Secrets en Streamlit.io

Para que el sistema de autenticación funcione correctamente en Streamlit.io, debe usar esta configuración exacta en sus secrets:

```toml
# === Conexión a Base de Datos (PostgreSQL) ===
[database]
host = "aws-1-us-east-1.pooler.supabase.com"
port = 6543
dbname = "postgres"
user = "postgres.gxezyjgbghfwjhdjaegz"
password = "12345"

# === IA de Google Gemini ===
[ai]
google_api_key = "AIzaSyA0g3loykmrQs1CQ8WOR4zbwOn25_09tJE"

# === Almacenamiento (Supabase Storage) ===
[supabase]
url = "https://gxezyjgbghfwjhdjaegz.supabase.co"
key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imd4ZXp5amdiZ2hmd2poZGphZWd6Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NzI5Nzg3MiwiZXhwIjoyMDcyODczODcyfQ.7t4xOxKLW74zZ2w1JZHjzR2-D_OjrDRK0E94gLRvVGk"

# === AUTENTICACIÓN (CRÍTICO) ===
[connections.supabase]
url = "https://gxezyjgbghfwjhdjaegz.supabase.co"
key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imd4ZXp5amdiZ2hmd2poZGphZWd6Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTcyOTc4NzIsImV4cCI6MjA3Mjg3Mzg3Mn0.GVAY_lRRleQ2e0WnHk5EPZ7nVLosYgyKh_43VCGg_Mg"
```

## 🔑 Tipos de Keys de Supabase

### Service Role Key (para storage y admin)
- **Uso**: Operaciones de almacenamiento y administración
- **Ubicación**: `[supabase]` section
- **Características**: Permisos completos, bypassa RLS

### Anon Key (para autenticación)
- **Uso**: Autenticación de usuarios y acceso público
- **Ubicación**: `[connections.supabase]` section 
- **Características**: Respeta RLS, permite auth.signUp() y auth.signIn()

## 🔧 Solución de Problemas

### Error: "Supabase URL not provided"
**Causa**: `st.connection("supabase")` no encuentra la configuración
**Solución**: Implementada función de fallback que usa conexión directa

### Error: "Email podría estar ya registrado"
**Posibles causas**:
1. Email ya existe en Supabase Auth
2. Políticas RLS bloqueando la operación
3. Configuración incorrecta de Supabase Auth

### Verificación de Configuración Supabase

1. **Auth Settings** en Supabase Dashboard:
   - ✅ Enable email confirmations (opcional)
   - ✅ Enable sign ups
   - ✅ Site URL configurada

2. **RLS Policies** para tabla `perfiles`:
   ```sql
   -- Permitir inserción para usuarios autenticados
   CREATE POLICY "Usuarios pueden crear su perfil" ON perfiles
   FOR INSERT WITH CHECK (auth.uid() = id);
   
   -- Permitir lectura para usuarios autenticados
   CREATE POLICY "Usuarios pueden leer su perfil" ON perfiles
   FOR SELECT USING (auth.uid() = id);
   
   -- Permitir actualización para usuarios autenticados
   CREATE POLICY "Usuarios pueden actualizar su perfil" ON perfiles
   FOR UPDATE USING (auth.uid() = id);
   ```

## 🚀 Mejoras Implementadas

### Sistema de Fallback
- Si `st.connection("supabase")` falla, usa conexión directa con `supabase-py`
- Mayor robustez en entornos de producción

### Manejo de Errores
- Mensajes específicos para diferentes tipos de error
- Logging detallado para debugging

### Configuración Flexible
- Detección automática del tipo de key
- Adaptación a diferentes configuraciones de Supabase

## 📝 Pasos para Resolver el Error Actual

1. **Verificar Secrets**: Asegúrese de que los secrets en Streamlit.io coincidan exactamente con la configuración de arriba

2. **Verificar Supabase Auth**: 
   - Vaya a Supabase Dashboard → Authentication → Settings
   - Confirme que "Enable sign ups" esté activado
   
3. **Verificar RLS Policies**:
   - Vaya a Supabase Dashboard → Table Editor → perfiles
   - Confirme que existan políticas para INSERT/SELECT/UPDATE

4. **Test de Conexión**:
   - Ejecute `verificar_auth.py` para diagnosticar problemas
   - Revise los logs en Streamlit.io

## 🎯 Resultado Esperado

Después de aplicar estas correcciones:
- ✅ Los usuarios podrán registrarse exitosamente
- ✅ El login funcionará correctamente  
- ✅ La gestión de perfiles estará operativa
- ✅ El sistema será robusto ante fallos de conexión

## 📞 Debug Adicional

Si el problema persiste, agregue este código temporal para debug:

```python
# En la función register_user, agregar:
st.write("DEBUG - URL:", st.secrets["connections"]["supabase"]["url"])
st.write("DEBUG - Key type:", "anon" if "anon" in st.secrets["connections"]["supabase"]["key"] else "other")
```

Esto ayudará a identificar si el problema está en la configuración o en la conectividad.