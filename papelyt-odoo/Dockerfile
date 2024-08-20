# Usar la misma versión de la imagen base de Odoo que estás utilizando
FROM odoo:17.0

# Cambiar al usuario root para instalar paquetes
USER root

# Actualizar pip y instalar dependencias
RUN pip3 install --upgrade pip && \
    pip3 install wheel && \
    pip3 install setuptools && \
    pip3 install cryptography==36.0.0 && \
    pip3 install xades==0.2.4 && \
    pip3 install xmlsig==0.1.9 && \
    pip3 install zeep

# Volver al usuario Odoo
USER odoo