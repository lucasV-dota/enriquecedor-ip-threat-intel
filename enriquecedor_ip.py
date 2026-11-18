import argparse
import time
import requests
import json
import os


def consultar_abuseipdb(ip, api_key):
    if not api_key:
        return {"aviso": "ABUSEIPDB_API_KEY no configurada en el entorno"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "puntaje_abuso": data.get("abuseConfidenceScore"),
            "total_reportes": data.get("totalReports"),
            "es_nodo_tor": data.get("isTor"),
            "tipo_uso": data.get("usageType"),
            "ultimo_reporte": data.get("lastReportedAt")
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"Fallo al consultar AbuseIPDB: {e}"}


parser = argparse.ArgumentParser(description="Busca info de las Ips")
parser.add_argument("-i", "--input", help="ruta del JSON", default="reporte_ataques.json")
parser.add_argument("-o", "--output", help="ruta del JSON de salida", default="reporte_enriquecido.json")

args = parser.parse_args()
api_key_abuse = os.environ.get("ABUSEIPDB_API_KEY")

try:
    with open(args.input, "r", encoding="utf-8") as f:
        datos = json.load(f)
except FileNotFoundError:
    print(f"No se encontro el archivo: '{args.input}'")
    exit(1)
   
for ip, info in  datos.items():
    print(f"[*]Consultado reputacion para {ip}...")
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,proxy,hosting"
    try:
        respuesta_web = requests.get(url, timeout=5)
        respuesta_web.raise_for_status()
        info_api = respuesta_web.json()

        if info_api.get("status") == "success":
            info["threat_intel"] = {
                "pais": info_api.get("country"),
                "ciudad": info_api.get("city"),
                "isp": info_api.get("isp"),
                "asn": info_api.get("as"),
                "es_proxy_vpn": info_api.get("proxy"),
                "es_hosting": info_api.get("hosting")
            }
        else:
            info["threat_intel"] = {"error": info_api.get("message", "Consulta fallida")}
    except requests.exceptions.RequestException as e:
        print(f"[-] Error de red consultando {ip}: {e}")
        info["threat_intel"] = {"error": f"Fallo de conexión: {e}"}
    info["reputacion_abuseipdb"] = consultar_abuseipdb(ip, api_key_abuse)
    time.sleep(1.5)
with open(args.output, "w", encoding="utf-8") as f_out:
    json.dump(datos, f_out, indent=4)

print(f"[*] Reporte enriquecido guardado en: '{args.output}'")
