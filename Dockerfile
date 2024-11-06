# Usar la misma versión de la imagen base de Odoo que estás utilizando
FROM odoo:18.0

USER root

# Establecer la variable de entorno para permitir instalaciones con pip
ENV PIP_BREAK_SYSTEM_PACKAGES=1

COPY requirements.txt /tmp/requirements.txt

# Actualizar pip e instalar dependencias desde requirements.txt
RUN pip3 install --upgrade pip && \
    pip3 install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt && \
    rm -rf /root/.cache/pip

# Volver al usuario Odoo
USER odoo

