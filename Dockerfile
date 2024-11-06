# Usar la misma versión de la imagen base de Odoo que estás utilizando
FROM odoo:18.0

USER root

ENV PIP_BREAK_SYSTEM_PACKAGES=1

COPY requirements.txt /tmp/requirements.txt

# Instalar dependencias desde requirements.txt sin actualizar pip
RUN pip3 install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt && \
    rm -rf /root/.cache/pip

USER odoo


