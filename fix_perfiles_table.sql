-- Script para agregar columnas necesarias a la tabla perfiles
-- Ejecute este script para agregar la columna email_contacto

DO $$
BEGIN
    -- Verificar si la tabla perfiles existe
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'perfiles') THEN
        RAISE NOTICE 'Tabla perfiles existe, verificando columnas...';
        
        -- Agregar columna email_contacto si no existe
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'perfiles'::regclass AND attname = 'email_contacto') THEN
            ALTER TABLE perfiles ADD COLUMN email_contacto VARCHAR(255);
            RAISE NOTICE 'Columna email_contacto agregada';
        END IF;
        
        -- Agregar columna telefono si no existe
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'perfiles'::regclass AND attname = 'telefono') THEN
            ALTER TABLE perfiles ADD COLUMN telefono VARCHAR(20);
            RAISE NOTICE 'Columna telefono agregada';
        END IF;
        
        -- Agregar columna especialidad si no existe (para abogados)
        IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'perfiles'::regclass AND attname = 'especialidad') THEN
            ALTER TABLE perfiles ADD COLUMN especialidad VARCHAR(100);
            RAISE NOTICE 'Columna especialidad agregada';
        END IF;
        
        -- Agregar índice en email_contacto para búsquedas rápidas
        IF NOT EXISTS (SELECT FROM pg_indexes WHERE tablename = 'perfiles' AND indexname = 'idx_perfiles_email_contacto') THEN
            CREATE INDEX idx_perfiles_email_contacto ON perfiles(email_contacto);
            RAISE NOTICE 'Índice en email_contacto creado';
        END IF;
        
    ELSE
        RAISE NOTICE 'Tabla perfiles no existe, debe ser creada primero';
    END IF;
END $$;