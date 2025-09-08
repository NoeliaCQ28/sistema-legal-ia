-- Script de Base de Datos Definitivo y Consistente
-- Este script NO BORRA DATOS. Utiliza ALTER TABLE y CREATE OR REPLACE
-- para asegurar que la estructura es la correcta.
-- Ejecuta este script completo una sola vez.

-- Parte 1: Asegurar que las tablas y columnas existan y sean consistentes

DO $$
BEGIN
    -- Crear tabla 'clientes' si no existe
    CREATE TABLE IF NOT EXISTS clientes (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(100),
        apellido VARCHAR(100),
        email VARCHAR(100),
        telefono VARCHAR(20),
        direccion TEXT
    );
    -- Renombrar 'id' a 'id_cliente' para consistencia
    IF EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'clientes'::regclass AND attname = 'id') THEN
        ALTER TABLE clientes RENAME COLUMN id TO id_cliente;
    END IF;

    -- Crear tabla 'abogados' si no existe
    CREATE TABLE IF NOT EXISTS abogados (
        id SERIAL PRIMARY KEY,
        nombre VARCHAR(100),
        apellido VARCHAR(100),
        especialidad VARCHAR(100),
        email VARCHAR(100),
        telefono VARCHAR(20)
    );
    -- Renombrar 'id' a 'id_abogado' para consistencia
    IF EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'abogados'::regclass AND attname = 'id') THEN
        ALTER TABLE abogados RENAME COLUMN id TO id_abogado;
    END IF;

    -- Crear tabla 'casos' si no existe
    CREATE TABLE IF NOT EXISTS casos (
        id SERIAL PRIMARY KEY,
        titulo VARCHAR(255),
        descripcion TEXT,
        estado VARCHAR(50) DEFAULT 'Abierto',
        fecha_apertura DATE DEFAULT CURRENT_DATE,
        id_cliente INT,
        id_abogado INT
    );
    -- Renombrar 'id' a 'id_caso' para consistencia
    IF EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'casos'::regclass AND attname = 'id') THEN
        ALTER TABLE casos RENAME COLUMN id TO id_caso;
    END IF;
    -- Asegurar que las columnas FK existan
    IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'casos'::regclass AND attname = 'id_cliente') THEN
        ALTER TABLE casos ADD COLUMN id_cliente INT;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid = 'casos'::regclass AND attname = 'id_abogado') THEN
        ALTER TABLE casos ADD COLUMN id_abogado INT;
    END IF;

    -- Crear tabla 'documentos' si no existe
    CREATE TABLE IF NOT EXISTS documentos (
        id_documento SERIAL PRIMARY KEY,
        nombre_archivo VARCHAR(255),
        descripcion TEXT,
        fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        id_caso INT,
        ruta_storage TEXT
    );
END $$;


-- Parte 2: Crear o Reemplazar los Procedimientos Almacenados

-- Procedimiento para crear un cliente
CREATE OR REPLACE PROCEDURE crear_cliente(
    p_nombre TEXT,
    p_apellido TEXT,
    p_email TEXT,
    p_telefono TEXT,
    p_direccion TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO clientes (nombre, apellido, email, telefono, direccion)
    VALUES (p_nombre, p_apellido, p_email, p_telefono, p_direccion);
END;
$$;

-- Procedimiento para crear un abogado
CREATE OR REPLACE PROCEDURE crear_abogado(
    p_nombre TEXT,
    p_apellido TEXT,
    p_especialidad TEXT,
    p_email TEXT,
    p_telefono TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO abogados (nombre, apellido, especialidad, email, telefono)
    VALUES (p_nombre, p_apellido, p_especialidad, p_email, p_telefono);
END;
$$;

-- Procedimiento para crear un caso
-- CORRECCIÓN: Se borra tanto el procedimiento como la función para evitar conflictos.
DROP PROCEDURE IF EXISTS crear_caso(VARCHAR, TEXT, INT, INT);
DROP FUNCTION IF EXISTS crear_caso(VARCHAR, TEXT, INT, INT);

CREATE OR REPLACE PROCEDURE crear_caso(
    p_titulo VARCHAR,
    p_descripcion TEXT,
    p_id_cliente INT,
    p_id_abogado INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO casos (titulo, descripcion, id_cliente, id_abogado, estado, fecha_apertura)
    VALUES (p_titulo, p_descripcion, p_id_cliente, p_id_abogado, 'Abierto', CURRENT_DATE);
END;
$$;

-- Procedimiento para actualizar el estado de un caso
-- CORRECCIÓN: Se borra el procedimiento antes de crearlo para evitar error de cambio de parámetro.
DROP PROCEDURE IF EXISTS actualizar_estado_caso(integer, character varying);

CREATE OR REPLACE PROCEDURE actualizar_estado_caso(
    p_id_caso INT,
    p_nuevo_estado VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE casos
    SET estado = p_nuevo_estado
    WHERE id_caso = p_id_caso;
END;
$$;

-- Procedimiento para crear un documento
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
$$;


-- Parte 3: Crear o Reemplazar la Función de Vista

-- Primero se borra para evitar conflictos de tipo de retorno
DROP FUNCTION IF EXISTS obtener_casos_detallados();

CREATE OR REPLACE FUNCTION obtener_casos_detallados()
RETURNS TABLE(
    id_caso INT,
    titulo VARCHAR,
    cliente VARCHAR,
    abogado VARCHAR,
    descripcion TEXT,
    estado VARCHAR,
    fecha_apertura TIMESTAMP
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        c.id_caso,
        c.titulo,
        (cl.nombre || ' ' || cl.apellido)::VARCHAR AS cliente_completo,
        (ab.nombre || ' ' || ab.apellido)::VARCHAR AS abogado_completo,
        c.descripcion,
        c.estado,
        CAST(c.fecha_apertura AS TIMESTAMP)
    FROM casos c
    LEFT JOIN clientes cl ON c.id_cliente = cl.id_cliente
    LEFT JOIN abogados ab ON c.id_abogado = ab.id_abogado
    ORDER BY c.fecha_apertura DESC;
END;
$$;

