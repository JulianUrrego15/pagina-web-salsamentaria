-- Actualización de la base de datos: anulaciones y devoluciones de ventas.
-- La app ya hace esto sola al arrancar; este archivo es solo para quien
-- prefiera aplicarlo a mano:  psql -U postgres -d salsamentar1a -f actualizar_bd.sql

ALTER TABLE ventas ADD COLUMN IF NOT EXISTS motivo_anulacion TEXT;
ALTER TABLE ventas ADD COLUMN IF NOT EXISTS fecha_anulacion TIMESTAMP;
ALTER TABLE ventas ADD COLUMN IF NOT EXISTS cod_usu_anula INTEGER REFERENCES usuarios(cod_usu);

CREATE TABLE IF NOT EXISTS devoluciones (
    cod_dev SERIAL PRIMARY KEY,
    cod_ven INTEGER NOT NULL REFERENCES ventas(cod_ven),
    cod_usu INTEGER NOT NULL REFERENCES usuarios(cod_usu),
    fecha TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    motivo VARCHAR(200) NOT NULL,
    total_devuelto NUMERIC(10,2) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS detalle_devolucion (
    cod_det_dev SERIAL PRIMARY KEY,
    cod_dev INTEGER NOT NULL REFERENCES devoluciones(cod_dev) ON DELETE CASCADE,
    cod_detalle INTEGER NOT NULL REFERENCES detalle_venta(cod_detalle),
    cantidad INTEGER NOT NULL CHECK (cantidad > 0),
    valor NUMERIC(10,2) NOT NULL
);
