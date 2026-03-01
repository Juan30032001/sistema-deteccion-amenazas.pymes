# --------------------------
# SISTEMA DE DETECCIÓN DE AMENAZAS PARA PYMES
# Código completo y corregido
# --------------------------
import pandas as pd
import numpy as np
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import streamlit as st


# --------------------------
# FUNCIÓN PARA PROCESAR EL ARCHIVO .PCAP
# --------------------------
def procesar_pcap(ruta_pcap):
    paquetes = rdpcap(ruta_pcap)
    datos_reales = []

    # Recorrer cada paquete y extraer información
    for paquete in paquetes:
        if IP in paquete:
            ip_layer = paquete[IP]
            tamano_paquete = len(paquete)
            protocolo = ip_layer.proto
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = ip_layer.payload.sport if hasattr(ip_layer.payload, "sport") else 0
            dst_port = ip_layer.payload.dport if hasattr(ip_layer.payload, "dport") else 0
            timestamp = paquete.time  # Timestamp en formato numérico

            # Detectar características de amenazas
            es_http = 1 if HTTPRequest in paquete or HTTPResponse in paquete else 0
            dominio_sospechoso = 1 if es_http and ("sospechoso" in str(paquete) or "fake" in str(paquete)) else 0
            es_ping_flood = 1 if (protocolo == 1 and tamano_paquete > 500) else 0

            # Clasificar tipo de amenaza
            tipo_amenaza = "Normal"
            if protocolo == 6 and tamano_paquete > 1000:
                tipo_amenaza = "Tráfico TCP grande (posible intrusión)"
            elif es_ping_flood:
                tipo_amenaza = "Ping Flood (DDoS)"
            elif dominio_sospechoso:
                tipo_amenaza = "Tráfico HTTP sospechoso (phishing)"
            elif src_port == 22 or dst_port == 22 and protocolo == 6:
                tipo_amenaza = "Intento de acceso SSH (sospechoso)"

            # Guardar datos en la lista
            datos_reales.append({
                "Timestamp": timestamp,
                "Trafico_MBs": round(tamano_paquete / 1024, 2),
                "Protocolo": protocolo,
                "Src_IP": src_ip,
                "Dst_IP": dst_ip,
                "Src_Puerto": src_port,
                "Dst_Puerto": dst_port,
                "Es_HTTP": es_http,
                "Es_Ping_Flood": es_ping_flood,
                "Dominio_Sospechoso": dominio_sospechoso,
                "Tipo_Amenaza": tipo_amenaza
            })

    # Convertir lista a DataFrame
    df = pd.DataFrame(datos_reales)
    
    if not df.empty:
        # Limpiar y procesar timestamps
        df["Timestamp"] = pd.to_numeric(df["Timestamp"], errors="coerce")
        df = df.dropna(subset=["Timestamp"])
        
        # Convertir a formato de hora y agrupar por minutos
        df["Hora"] = pd.to_datetime(df["Timestamp"], unit="s", errors="coerce").dt.floor("min")
        df = df.dropna(subset=["Hora"])
        
        # Calcular conexiones por minuto
        conexiones_por_min = df.groupby("Hora")["Timestamp"].count().reset_index(name="Conexiones_por_min")
        df = pd.merge(df, conexiones_por_min, on="Hora", how="left")
        df["Conexiones_por_min"] = df["Conexiones_por_min"].fillna(1)

        # Detectar escaneo de puertos
        ip_puerto_counts = df.groupby(["Src_IP", "Hora"])["Dst_Puerto"].nunique().reset_index(name="Puertos_Distintos")
        df = pd.merge(df, ip_puerto_counts, on=["Src_IP", "Hora"], how="left")
        df["Es_Escaneo_Puertos"] = np.where(df["Puertos_Distintos"] > 10, 1, 0)
        df.loc[df["Es_Escaneo_Puertos"] == 1, "Tipo_Amenaza"] = "Escaneo de Puertos"
    
    return df


# --------------------------
# FUNCIÓN PARA ENTRENAR EL MODELO DE ML
# --------------------------
def entrenar_modelo(df):
    if df.empty:
        return None, None, 0.0, ""
    
    # Preparar datos para el modelo
    le = LabelEncoder()
    df["Tipo_Amenaza_Cod"] = le.fit_transform(df["Tipo_Amenaza"])
    
    # Características para entrenar
    caracteristicas = ["Trafico_MBs", "Protocolo", "Es_HTTP", "Es_Ping_Flood", "Conexiones_por_min"]
    X = df[caracteristicas]
    y = df["Tipo_Amenaza_Cod"]
    
    # Dividir datos y entrenar
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    modelo = RandomForestClassifier(n_estimators=150, random_state=42)
    modelo.fit(X_train, y_train)
    
    # Calcular métricas
    precision = accuracy_score(y_test, modelo.predict(X_test))
    reporte = classification_report(y_test, modelo.predict(X_test), target_names=le.classes_)
    
    return modelo, le, precision, reporte


# --------------------------
# INTERFAZ VISUAL CON STREAMLIT
# --------------------------
def main():
    st.title("🔒 SISTEMA DE DETECCIÓN DE AMENAZAS PARA PYMES")
    st.subheader("Analiza tu archivo .pcap para detectar tráfico malicioso")

    # Cargar archivo
    archivo = st.file_uploader("Sube tu archivo .pcap o .pcapng", type=["pcap", "pcapng"])
    
    if archivo is not None:
        # Guardar archivo temporalmente
        with open("archivo_temporal.pcap", "wb") as f:
            f.write(archivo.getbuffer())
        
        st.success(f"Archivo '{archivo.name}' cargado correctamente!")
        st.info("Procesando datos... ⏳")
        
        # Procesar archivo y entrenar modelo
        df = procesar_pcap("archivo_temporal.pcap")
        modelo, le, precision, reporte = entrenar_modelo(df)
        
        if df.empty:
            st.error("❌ No se encontraron paquetes IP válidos en el archivo")
        else:
            st.success("✅ Datos procesados correctamente!")
            
            # Mostrar datos extraídos
            st.subheader("📊 Datos extraídos del tráfico")
            st.dataframe(df[["Hora", "Src_IP", "Dst_IP", "Protocolo", "Tipo_Amenaza"]].head(20))
            
            # Mostrar resultados del modelo
            st.subheader("🤖 Resultados del modelo de Machine Learning")
            st.metric("Precisión del modelo", f"{precision:.2f}")
            st.text("Reporte de clasificación:")
            st.text(reporte)
            
            # Mostrar amenazas detectadas
            st.subheader("⚠️ Amenazas Detectadas")
            amenazas = df[df["Tipo_Amenaza"] != "Normal"]
            
            if len(amenazas) > 0:
                st.dataframe(amenazas[["Hora", "Src_IP", "Dst_IP", "Tipo_Amenaza"]])
            else:
                st.info("No se detectaron amenazas en el tráfico analizado ✅")


# --------------------------
# EJECUTAR LA APLICACIÓN
# --------------------------
if __name__ == "__main__":
    # Instalar dependencias si faltan (solo la primera vez)
    try:
        import streamlit
    except ImportError:
        import subprocess
        subprocess.check_call(["pip", "install", "streamlit", "pandas", "numpy", "scapy", "scikit-learn"])
    
    main()