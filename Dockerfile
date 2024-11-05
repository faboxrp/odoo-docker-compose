# Usar la misma versión de la imagen base de Odoo que estás utilizando
FROM odoo:18.0

# Cambiar al usuario root para instalar paquetes
USER root

# Copiar el archivo requirements.txt al contenedor
COPY requirements.txt /tmp/requirements.txt

# Actualizar pip y instalar dependencias desde requirements.txt
RUN pip3 install --upgrade pip && \
    pip3 install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt && \
    rm -rf /root/.cache/pip


# Volver al usuario Odoo
USER odoo
