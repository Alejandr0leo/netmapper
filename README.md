# 🛰️ NetMapper — Escáner de red y mapa de activos

NetMapper descubre **hosts, puertos y servicios** en una red mediante *TCP connect scan*
usando **solo la librería estándar de Python** (sockets + hilos, cero dependencias para el
motor). Genera un inventario de activos, un resumen de **superficie de ataque** y reportes
en terminal, Markdown/JSON y un dashboard visual.

> Proyecto de portafolio orientado a roles de **Redes / SOC / Seguridad ofensiva (recon)**.

> ⚠️ **Uso responsable:** NetMapper está pensado para auditar **redes propias o con
> autorización explícita**. Por defecto solo permite objetivos privados/de laboratorio;
> los objetivos públicos requieren el flag `--authorized`. Escanear redes ajenas sin
> permiso puede ser ilegal.

---

## ✨ ¿Qué hace?

- **Descubre hosts vivos** probando puertos comunes (sin requerir root).
- **Escanea puertos** por TCP connect, de forma concurrente con hilos.
- **Identifica servicios** combinando el puerto con *banner grabbing* ligero.
- **Resume la superficie de ataque** y marca **exposiciones notables** (telnet, RDP, SMB, Redis sin auth, etc.).
- **Guardrail de seguridad** que limita el alcance a redes propias salvo autorización explícita.
- Reportes en **terminal, Markdown y JSON**, más un **dashboard** con mapa de activos.

---

## 🚀 Uso rápido

```bash
# Escanear tu red local (top 20 puertos)
python cli.py 192.168.1.0/24

# Un host con un set de puertos y reporte
python cli.py 127.0.0.1 --ports top50 --markdown reporte.md

# Puertos específicos
python cli.py 192.168.1.10 --ports 22,80,443,3389

# Dashboard visual
pip install -r requirements.txt   # solo para el dashboard (streamlit/pandas)
streamlit run dashboard.py
```

Grupos de puertos: `top20`, `top50`, `web`, un rango `1-1024` o una lista `22,80,443`.

### Ejemplo de salida (terminal)

```
Objetivo: 127.0.0.1  ·  1 IP(s)  ·  6 puerto(s) por host

● 127.0.0.1  (2 abierto/s)
     8000/tcp  http  HTTP/1.0 200 OK
     8080/tcp  http  HTTP/1.0 200 OK

Resumen: 1 host(s), 2 puerto(s) abierto(s).
```

---

## 🧱 Arquitectura

```
netmapper/
├── netmapper/
│   ├── scanner.py    # Descubrimiento de hosts + escaneo de puertos (sockets, hilos)
│   ├── services.py   # Mapa puerto→servicio, grupos y banner grabbing
│   ├── report.py     # Inventario + superficie de ataque + reportes MD/JSON
│   └── safety.py     # Guardrail: solo redes propias/autorizadas
├── cli.py            # Ejecución por terminal
├── dashboard.py      # Dashboard visual (Streamlit)
└── requirements.txt  # Solo para el dashboard (el motor no necesita nada)
```

**Motor:** Python estándar (`socket`, `concurrent.futures`, `ipaddress`).
**Dashboard:** Streamlit + pandas.

### Sobre el método de escaneo
Se usa *TCP connect scan* (no requiere privilegios de root). Por cada puerto:
conexión exitosa → `open`; conexión rechazada → `closed` (host vivo); timeout → `filtered`.

---

## 🗺️ Roadmap

- [ ] Detección de versión más rica (fingerprints por servicio).
- [ ] Exportación a formato compatible con Nmap (XML) y a CSV.
- [ ] Gráfo de red interactivo en el dashboard.
- [ ] Escaneo UDP básico para servicios comunes (DNS, SNMP).

---

## 👤 Autor

**Nikolay Alejandro León Duarte** — Estudiante de Ingeniería de Sistemas (redes, ciberseguridad, Python)
GitHub: [github.com/Alejandr0leo](https://github.com/Alejandr0leo)

---

*Proyecto educativo / de portafolio. Úsalo únicamente sobre redes propias o con autorización por escrito.*
