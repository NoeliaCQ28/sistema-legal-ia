-- Script de corrección para la tabla documentos
-- Ejecute este script para arreglar la estructura de la tabla documentos

DO $$
BEGIN
    -- Verificar si la tabla documentos existe
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'documentos') THEN
        RAISE NOTICE 'Tabla documentos existe, verificando columnas...';
        
        -- Agregar columna id_caso si no existe
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'documentos'::regclass AND attname = 'id_caso') THEN
            ALTER TABLE documentos ADD COLUMN id_caso INT;
            RAISE NOTICE 'Columna id_caso agregada';
        END IF;
        
        -- Agregar columna descripcion si no existe
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'documentos'::regclass AND attname = 'descripcion') THEN
            ALTER TABLE documentos ADD COLUMN descripcion TEXT;
            RAISE NOTICE 'Columna descripcion agregada';
        END IF;
        
        -- Agregar columna ruta_storage si no existe
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'documentos'::regclass AND attname = 'ruta_storage') THEN
            ALTER TABLE documentos ADD COLUMN ruta_storage TEXT;
            RAISE NOTICE 'Columna ruta_storage agregada';
        END IF;
        
        -- Agregar columna nombre_archivo si no existe
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'documentos'::regclass AND attname = 'nombre_archivo') THEN
            ALTER TABLE documentos ADD COLUMN nombre_archivo VARCHAR(255);
            RAISE NOTICE 'Columna nombre_archivo agregada';
        END IF;
        
        -- Agregar columna fecha_subida si no existe
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'documentos'::regclass AND attname = 'fecha_subida') THEN
            ALTER TABLE documentos ADD COLUMN fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
            RAISE NOTICE 'Columna fecha_subida agregada';
        END IF;
        
        -- Agregar columna id_documento si no existe (como PRIMARY KEY)
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'documentos'::regclass AND attname = 'id_documento') THEN
            -- Primero agregar la columna
            ALTER TABLE documentos ADD COLUMN id_documento SERIAL;
            -- Luego hacer que sea PRIMARY KEY si no hay una ya
            IF NOT EXISTS (SELECT FROM pg_constraint WHERE conrelid = 'documentos'::regclass AND contype = 'p') THEN
                ALTER TABLE documentos ADD PRIMARY KEY (id_documento);
            END IF;
            RAISE NOTICE 'Columna id_documento agregada como PRIMARY KEY';
        END IF;
        
    ELSE
        -- Crear la tabla completa si no existe
        CREATE TABLE documentos (
            id_documento SERIAL PRIMARY KEY,
            nombre_archivo VARCHAR(255),
            descripcion TEXT,
            fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            id_caso INT,
            ruta_storage TEXT
        );
        RAISE NOTICE 'Tabla documentos creada completamente';
    END IF;
    
    RAISE NOTICE 'Corrección de tabla documentos completada';
END $$;

-- Verificar la estructura final
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'documentos'
ORDER BY ordinal_position;