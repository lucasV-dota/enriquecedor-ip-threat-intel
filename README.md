# Enriquecedor de Threat Intelligence (enriquecedor_ip.py)

Herramienta CLI en Python diseñada para consumir reportes de incidentes en formato **JSON** (como los generados por `detector_ssh.py`), consultar inteligencia de amenazas y geolocalización en tiempo real mediante la API de **ip-api.com**, y exportar un reporte consolidado.

## Características

- **Integración modular por JSON:** Lee reportes de alertas (`json.load`) y enriquece cada dirección IP conservando los metadatos originales del incidente (intentos y usuarios atacados).
- **Contexto de red y geolocalización:** Extrae país, ciudad, ISP, número de Sistema Autónomo (`ASN`) y detección de tráfico anónimo (`proxy`/`VPN`/`Tor`) o infraestructura en la nube (`hosting`).
- **Tolerancia a fallos y control de tasa:** Maneja excepciones de red (`RequestException`), verifica códigos de estado HTTP (`raise_for_status`), registra rechazos de IPs privadas y respeta límites de frecuencia mediante pausas configuradas (`time.sleep`).

## Requisitos e instalación

- Python 3.8 o superior
- Librería externa `requests`
- Instalar dependencias: `pip install -r requirements.txt`

## Uso

- Ejecución con valores por defecto (`reporte_ataques.json` -> `reporte_enriquecido.json`): `python3 enriquecedor_ip.py`
- Especificar archivos personalizados: `python3 enriquecedor_ip.py -i alerta_ssh.json -o reporte_final.json`
