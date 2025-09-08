-- Script para corregir el procedimiento crear_documento
-- Detecta automáticamente si usar 'ruta_storage' o 'url_almacenamiento'

DO $proc$
DECLARE
    column_exists_ruta_storage BOOLEAN := FALSE;
    column_exists_url_almacenamiento BOOLEAN := FALSE;
BEGIN
    -- Verificar qué columna existe
    SELECT EXISTS (
        SELECT 1 FROM pg_attribute 
        WHERE attrelid = 'documentos'::regclass 
        AND attname = 'ruta_storage'
    ) INTO column_exists_ruta_storage;
    
    SELECT EXISTS (
        SELECT 1 FROM pg_attribute 
        WHERE attrelid = 'documentos'::regclass 
        AND attname = 'url_almacenamiento'
    ) INTO column_exists_url_almacenamiento;
    
    -- Borrar procedimiento existente
    DROP PROCEDURE IF EXISTS crear_documento(character varying, text, integer, text);
    
    -- Crear procedimiento basado en la estructura actual
    IF column_exists_url_almacenamiento THEN
        -- Usar url_almacenamiento
        EXECUTE '
        CREATE OR REPLACE PROCEDURE crear_documento(
            p_nombre_archivo VARCHAR,
            p_descripcion TEXT,
            p_id_caso INT,
            p_ruta_storage TEXT
        )
        LANGUAGE plpgsql
        AS $$
        BEGIN
            INSERT INTO documentos (nombre_archivo, descripcion, id_caso, url_almacenamiento)
            VALUES (p_nombre_archivo, p_descripcion, p_id_caso, p_ruta_storage);
        END;
        $$;';
        
        RAISE NOTICE 'Procedimiento creado usando columna url_almacenamiento';
        
    ELSIF column_exists_ruta_storage THEN
        -- Usar ruta_storage
        EXECUTE '
        CREATE OR REPLACE PROCEDURE crear_documento(
            p_nombre_archivo VARCHAR,
            p_descripcion TEXT,
            p_id_caso INT,
            p_ruta_storage TEXT
        )
        LANGUAGE plpgsql
        AS $$
        BEGIN
            INSERT INTO documentos (nombre_archivo, descripcion, id_caso, ruta_storage)
            VALUES (p_nombre_archivo, p_descripcion, p_id_caso, p_ruta_storage);
        END;
        $$;';
        
        RAISE NOTICE 'Procedimiento creado usando columna ruta_storage';
        
    ELSE
        RAISE EXCEPTION 'No se encontró ni ruta_storage ni url_almacenamiento en la tabla documentos';
    END IF;
    
END $proc$;

-- Mostrar la estructura actual para verificación
SELECT 
    column_name, 
    data_type, 
    is_nullable,
    CASE WHEN is_nullable = 'NO' THEN 'Required' ELSE 'Optional' END as required
FROM information_schema.columns
WHERE table_name = 'documentos'
ORDER BY ordinal_position;