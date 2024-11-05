#######################################
# 1. Error de carga de firma electrónica .p12
# 1.1 En el addon l10n_ec_account_edi archivo/models, del archivo "sri_key_type.py" reemplazar el codigo default (comentado a continuación) por lo siguiente:

# código a reemplazar (todo lo comentado con dos ##):

# # KEY_TO_PEM_CMD = (
# #     "openssl pkcs12 -nocerts -in %s -out %s -passin pass:%s -passout pass:%s"
# # )


# # def convert_key_cer_to_pem(key, password):
# #     # TODO compute it from a python way
# #     with NamedTemporaryFile(
# #         "wb", suffix=".key", prefix="edi.ec.tmp."
# #     ) as key_file, NamedTemporaryFile(
# #         "rb", suffix=".key", prefix="edi.ec.tmp."
# #     ) as keypem_file:
# #         key_file.write(key)
# #         key_file.flush()
# #         command = KEY_TO_PEM_CMD % (
# #             key_file.name, keypem_file.name, password, password)
# #         subprocess.call(command.split())
# #         key_pem = keypem_file.read().decode()
# #     return key_pem


#  código nuevo a ingresar:


openssl_config = """
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
"""


def convert_key_cer_to_pem(key, password):
    # TODO compute it from a python way
    # Crear un archivo de configuración temporal para OpenSSL
    with NamedTemporaryFile("w", delete=False) as config_file:
        config_file.write(openssl_config)
        config_path = config_file.name

    try:
        # Crear archivos temporales para la clave y la clave en formato PEM
        with NamedTemporaryFile("wb", suffix=".key", prefix="edi.ec.tmp.", delete=False) as key_file, \
                NamedTemporaryFile("rb", suffix=".pem", prefix="edi.ec.tmp.", delete=False) as keypem_file:

            key_file.write(key)
            key_file.flush()

            # Logs de los nombres de los archivos temporales y la contraseña, descomentar si se requiere (para debuggin)
            # _logger.info("Key file path: %s", key_file.name)
            # _logger.info("PEM file path: %s", keypem_file.name)
            # _logger.info("Password for key decryption: %s", password)

            # Construye y loguea el comando completo antes de ejecutarlo
            command = f"OPENSSL_CONF={config_path} openssl pkcs12 -nocerts -in {key_file.name} -out {keypem_file.name} -passin pass:{password} -passout pass:{password}"
            # _logger.info("OpenSSL Command: %s", command)

            # Ejecutar el comando y capturar la salida
            process = subprocess.run(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if process.returncode != 0:
                _logger.error(
                    "OpenSSL command failed with stderr: %s", process.stderr.decode())
                _logger.error(
                    "OpenSSL command failed with stdout: %s", process.stdout.decode())

            keypem_file.seek(0)  # Regresa al principio del archivo para leerlo
            key_pem = keypem_file.read().decode()
            # _logger.info("Extracted PEM: %s", key_pem[:100])

            return key_pem

    finally:
        # Eliminar archivos temporales
        os.remove(config_path)
        os.remove(key_file.name)
        os.remove(keypem_file.name)


# 1.1 En el mismo archivo, importar "os" al inicio del archivo
"import os"  # (sin comillas)


##############################
# 2. Error de reenvío infinito de correos en un cronjob cuando no se autoriza el xml a la primera vez:
# En el addon l10n_ec_account_edi/modules archivo "account_edi_document.py" agregar la linea...
account_move.write({"is_move_sent": True})

# ...despues del codigo existente:
# for account_move in account_moves:
#     account_move.l10n_ec_send_email()
#     account_move.write({"is_move_sent": True})  # <<<----- nueva linea
