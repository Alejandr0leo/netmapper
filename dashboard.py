"""
dashboard.py — Mapa de activos visual de NetMapper (Streamlit).

Uso:
    streamlit run dashboard.py
"""

import pandas as pd
import streamlit as st

from netmapper import scan, expand_targets, guard_targets, AuthorizationError
from netmapper.services import ports_for, RISKY_SERVICES
from netmapper.report import attack_surface

st.set_page_config(page_title="NetMapper — Mapa de activos", page_icon="🛰️", layout="wide")

st.title("🛰️ NetMapper — Mapa de activos de red")
st.caption("Descubrimiento de hosts, puertos y servicios por TCP connect. Solo redes propias o autorizadas.")

with st.sidebar:
    st.header("Escaneo")
    target = st.text_input("Objetivo (IP / CIDR / host)", value="127.0.0.1")
    group = st.selectbox("Puertos", ["top20", "top50", "web"], index=0)
    timeout = st.slider("Timeout por puerto (s)", 0.3, 2.0, 0.8, 0.1)
    authorized = st.checkbox("Tengo autorización para objetivos públicos", value=False)
    go = st.button("Escanear", type="primary")
    st.caption("⚠️ Escanear redes ajenas sin permiso puede ser ilegal.")

if go:
    ips = expand_targets(target)
    try:
        guard_targets(ips, authorized)
    except AuthorizationError as e:
        st.error(str(e))
        st.stop()

    with st.spinner(f"Escaneando {len(ips)} IP(s)..."):
        hosts = scan(ips, ports_for(group), timeout=timeout)

    if not hosts:
        st.warning("No se detectaron hosts vivos / puertos abiertos.")
        st.stop()

    surf = attack_surface(hosts)
    c1, c2, c3 = st.columns(3)
    c1.metric("Hosts vivos", surf["hosts_vivos"])
    c2.metric("Puertos abiertos", surf["puertos_abiertos"])
    c3.metric("Exposiciones notables", len(surf["exposiciones_notables"]))
    st.divider()

    if surf["exposiciones_notables"]:
        st.subheader("⚠️ Exposiciones notables")
        st.dataframe(pd.DataFrame(surf["exposiciones_notables"]),
                     use_container_width=True, hide_index=True)

    st.subheader("Mapa de activos")
    cols = st.columns(min(3, len(hosts)))
    for i, h in enumerate(hosts):
        with cols[i % len(cols)]:
            risky = any(p.service in RISKY_SERVICES for p in h.open_ports)
            border = "#e67e22" if risky else "#27ae60"
            chips = "".join(
                f"<span style='display:inline-block;margin:2px;padding:2px 8px;"
                f"border-radius:10px;background:#3498db22;font-size:12px'>"
                f"{p.port} {p.service}</span>"
                for p in h.open_ports
            )
            st.markdown(
                f"<div style='border:1px solid {border};border-radius:8px;padding:10px;margin-bottom:8px'>"
                f"<b>🖥️ {h.ip}</b><br><small>{len(h.open_ports)} puerto(s)</small><br>{chips}</div>",
                unsafe_allow_html=True,
            )

    st.subheader("Detalle")
    rows = [{"Host": h.ip, "Puerto": p.port, "Servicio": p.service, "Banner": p.banner}
            for h in hosts for p in h.open_ports]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

st.caption("NetMapper v0.1 · proyecto de portafolio — github.com/Alejandr0leo")
