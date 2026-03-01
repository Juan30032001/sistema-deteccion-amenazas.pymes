🛡️ Sistema de Detección de Amenazas para PYMES
 
Un proyecto diseñado para analizar archivos de captura de tráfico de red ( .pcap / .pcapng ) y detectar patrones de amenazas comunes, ideal para pequeñas y medianas empresas que buscan monitorear la seguridad de su red de forma sencilla y efectiva.
 
📋 Características Principales
 
- Carga y procesamiento de archivos  .pcap  y  .pcapng 

- Extracción de datos clave: direcciones IP, puertos, protocolos, tamaño de paquetes y timestamps

- Detección automática de amenazas frecuentes:

- Escaneo de puertos

- Tráfico TCP grande (posible intento de intrusión)

- Intentos de acceso SSH sospechosos

- Tráfico HTTP con dominios sospechosos

- Ping Flood (ataque DDoS básico)

- Clasificación de tráfico mediante modelo de Machine Learning

- Interfaz visual intuitiva desarrollada con Streamlit
 
🚀 Guía de Uso
 
1. Instalación de Dependencias
 
Primero, clona el repositorio o descarga todos los archivos del proyecto. Luego, instala las librerías necesarias ejecutando en la terminal:
 
 pip install -r requirements.txt
 
2. Ejecutar el Sistema
 
Inicia la interfaz visual con el siguiente comando:
 
 python -m streamlit run deteccion_amenazas_pymes.py
 
3. Analizar Tráfico de Red
 
- Abre tu navegador y ve a la dirección que muestre Streamlit (generalmente  http://localhost:8501 )

- Sube tu archivo de captura ( .pcap  o  .pcapng )

- Espera a que se complete el procesamiento

- Revisa los datos extraídos, los resultados del modelo y las amenazas detectadas
  
🛠️ Tecnologías Utilizadas
 
- Python: Lenguaje de programación principal

- Streamlit: Para la creación de la interfaz visual interactiva

- Scapy: Para leer y analizar archivos de captura de red

- Pandas/Numpy: Para el manejo y procesamiento de datos

- Scikit-learn: Para el desarrollo del modelo de Machine Learning (Random Forest Classifier)
 
📈 Mejoras Futuras Planificadas
 
- Aumentar la precisión del modelo con conjuntos de datos más amplios y diversos

- Agregar detección de más tipos de amenazas (ej: malware en tráfico HTTPS, phishing por correo electrónico)

- Implementar la exportación de resultados en formatos PDF y CSV

- Desarrollar un módulo de monitoreo en tiempo real de la red