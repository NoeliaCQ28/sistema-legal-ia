# Sistema de Autenticación LegalIA 🔐

## Descripción General

El sistema LegalIA ahora incluye un sistema completo de autenticación integrado con Supabase Auth que protege todas las funcionalidades de la aplicación.

## Características Implementadas

### ✅ Autenticación Completa
- **Registro de usuarios** con validación de email y contraseña
- **Inicio de sesión** con credenciales de Supabase Auth
- **Cierre de sesión** con limpieza completa de sesión
- **Verificación de sesión** con tokens JWT

### ✅ Gestión de Perfiles
- **Integración con tabla `perfiles`** existente en la base de datos
- **Actualización de información personal** (nombre completo)
- **Gestión de roles** (usuario/admin)
- **Cambio de contraseña** desde la interfaz

### ✅ Protección de Rutas
- **Verificación automática** de autenticación en todas las páginas
- **Redirección automática** al login si no está autenticado
- **Información del usuario** visible en la sidebar

## Configuración Necesaria

### 1. Dependencias Instaladas
```txt
streamlit-authenticator
bcrypt
PyJWT
st-supabase-connection
```

### 2. Configuración de Secrets
El archivo de configuración debe incluir la sección `[connections.supabase]` que ya tienes configurada:

```toml
[connections.supabase]
url = "https://gxezyjgbghfwjhdjaegz.supabase.co"
key = "tu_service_role_key_aqui"
```

### 3. Tabla de Perfiles
La tabla `perfiles` ya está creada y se integra automáticamente:

```sql
CREATE TABLE IF NOT EXISTS perfiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    nombre_completo TEXT,
    rol VARCHAR(50) DEFAULT 'usuario'
);
```

## Flujo de Usuario

### 🔑 Primer Acceso
1. El usuario accede a la aplicación
2. Se muestra la pantalla de login/registro
3. Puede crear una cuenta nueva o iniciar sesión
4. Después del registro, debe confirmar su email (dependiendo de la configuración de Supabase)

### 👤 Sesión Activa
1. Usuario autenticado ve todas las funcionalidades
2. Información del usuario aparece en la sidebar
3. Puede acceder a "Mi Perfil" para gestionar su cuenta
4. Puede cerrar sesión cuando desee

### 🛡️ Seguridad
- **Tokens JWT** con expiración de 24 horas
- **Verificación automática** de tokens en cada carga
- **Limpieza completa** de sesión al cerrar
- **Validación de contraseñas** (mínimo 6 caracteres)

## Uso de la Autenticación

### Para Usuarios
1. **Registrarse**: Completar el formulario de registro con nombre, email y contraseña
2. **Iniciar Sesión**: Usar email y contraseña registrados
3. **Gestionar Perfil**: Ir a "Mi Perfil" para actualizar información
4. **Cerrar Sesión**: Usar el botón en la sidebar

### Para Administradores
- Los usuarios con rol "admin" pueden cambiar su propio rol
- Futuras mejoras incluirán gestión de usuarios desde una interfaz admin

## Mejoras Futuras Sugeridas

### 🔮 Próximas Características
1. **Panel de Administración**
   - Gestión de todos los usuarios
   - Asignación de roles
   - Estadísticas de uso

2. **Auditoría y Logs**
   - Registro de acciones por usuario
   - Historial de cambios en casos
   - Logs de acceso

3. **Roles Avanzados**
   - Abogado: Acceso solo a sus casos
   - Cliente: Acceso solo a sus propios casos
   - Admin: Acceso completo

4. **Recuperación de Contraseña**
   - Reset de contraseña por email
   - Verificación de email automática

## Solución de Problemas

### ❌ Error de Conexión a Supabase
- Verificar que la URL y key en secrets sean correctas
- Asegurarse de usar el Service Role Key, no el Anon Key
- Comprobar que Supabase Auth esté habilitado

### ❌ Usuario No Puede Registrarse
- Verificar configuración de Supabase Auth
- Revisar políticas de seguridad (RLS) en Supabase
- Comprobar que la tabla `perfiles` exista

### ❌ Sesión Se Cierra Automáticamente
- Normal: Los tokens expiran en 24 horas
- Verificar que no haya errores en la consola del navegador
- Revisar la configuración JWT

## Códigos de Respuesta

### ✅ Registro Exitoso
- Mensaje: "¡Cuenta creada exitosamente! Revise su email para confirmar y luego inicie sesión."
- El usuario puede proceder a iniciar sesión

### ✅ Login Exitoso
- Mensaje: "¡Bienvenido, [Nombre del Usuario]!"
- Redirección automática al dashboard

### ❌ Credenciales Incorrectas
- Mensaje: "Email o contraseña incorrectos"
- Verificar email y contraseña

## Contacto y Soporte

Para cualquier problema con la autenticación:
1. Verificar la configuración de Supabase
2. Revisar los logs de error en la consola
3. Comprobar que todas las dependencias estén instaladas
4. Verificar que la tabla `perfiles` esté correctamente configurada

---

**LegalIA v1.1** - Sistema de Gestión Legal con Autenticación Integrada