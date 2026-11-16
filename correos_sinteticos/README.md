# Correos sintéticos de Tero

Buzón sintético que se usó para evaluar el motor de detección completo (las seis capas) del Proyecto Final de Ingeniería *Tero*. Ningún correo es real. Las empresas, las personas y las conversaciones se inventaron para el proyecto.

## Contenido

| Archivo | Qué es |
|---|---|
| `datos/correos_sinteticos.jsonl` | Los 3.215 correos, uno por línea en JSON. |
| `datos/correos_sinteticos.csv` | Lo mismo en CSV. Las columnas con listas u objetos van como JSON. |
| `datos/escenarios.csv` | Los 24 escenarios etiquetados: 18 de fraude y 6 legítimos. |
| `generador/` | El código que genera el buzón: `specs.py`, `generator.py` y `attacks.py`. |

## Composición

- **2 organizaciones ficticias**:
  - `tenant-andina`, una distribuidora con 2.377 correos;
  - `tenant-rivas`, un estudio contable con 838 correos.
- **3.147 correos de historial**: 90 días de tráfico normal entre empleados, proveedores, clientes y organismos. Sirven para construir los perfiles de remitente y de relación. No llevan etiqueta.
- **44 correos recientes normales**, sin etiqueta.
- **24 escenarios etiquetados** en `ground_truth` y `scenario`:
  - **18 de fraude**:
    - fraude del CEO por nombre visible (BEC);
    - cambio de CBU dentro de un hilo legítimo;
    - homógrafos y homoglifos cirílicos;
    - reply-to divergente;
    - factura falsa con adjunto;
    - AFIP/ARCA falso;
    - phishing bancario masivo;
    - robo de credenciales;
    - cuenta comprometida;
    - gift cards;
    - ráfaga desde un remitente nuevo, entre otros.
  - **6 legítimos difíciles**: correos que parecen sospechosos pero no lo son, como un cambio de CBU verificado, un gerente con urgencia, un proveedor nuevo o un correo real de ARCA.
  - `expected_layers` indica qué capas del motor debería disparar cada fraude.

## Campos principales

`tenant_id`, `mailbox`, `sender_email`, `sender_display`, `reply_to`, `recipients`, `cc`, `subject`, `body_text`, `sent_at`, `received_at`, `thread_id`, `in_reply_to`, `headers`, `attachments` (solo metadatos), `spf`/`dkim`/`dmarc`, `is_history`, `ground_truth`, `scenario`, `expected_layers`.

## Reproducibilidad

La generación es determinista:

- semilla `AP_RANDOM_SEED=42`;
- fecha de referencia fija `2026-08-19T15:00:00`.

Desde el repositorio de Tero se regenera con:

```bash
make seed
```

Se verificó que regenerar en una base vacía da exactamente los mismos archivos de esta carpeta, byte a byte.

Los archivos de `generador/` importan otros módulos del paquete `antiphishing`: el calendario hábil argentino, la persistencia y la anonimización. Por eso se incluyen para leerlos. Para ejecutarlos hace falta el repositorio completo.

## Licencia

CC BY 4.0.
