import argparse
import time
import requests
import json

parser = argparse.ArgumentParser(description="Busca info de las Ips")
parser.add_argument("-i", "--input", help="ruta del JSON", default="reporte_ataques.json")
parser.add_argument("-o", "--output", help="ruta del JSON de salida", default="reporte_enriquecido.json")

args = parser.parse_args()

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
    time.sleep(1.5)
with open(args.output, "w", encoding="utf-8") as e:
    json.dump(datos, e, indent=4)

print(f"[*] Reporte enriquecido guardado en: '{args.output}'")
