
from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import base64
import binascii

app = Flask(__name__)

@app.route("/")
def inicio():
    return render_template("index.html")


@app.route("/laboratorio", methods=["POST"])
def laboratorio():
    mensaje = request.form.get("mensaje", "").strip()
    accion = request.form.get("accion", "")

    resultado = {}
    clave_privada = None
    clave_publica = None

    try:
        if not mensaje:
            raise ValueError("Debes escribir un mensaje.")

        if len(mensaje.encode("utf-8")) > 190:
            raise ValueError(
                "El mensaje supera el límite de 190 bytes "
                "para esta demostración RSA de 2048 bits."
            )

        # Generar un par de claves RSA
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        clave_publica = clave_privada.public_key()

        if accion == "cifrar":
            cifrado = clave_publica.encrypt(
                mensaje.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            descifrado = clave_privada.decrypt(
                cifrado,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            resultado["mensaje_cifrado"] = base64.b64encode(
                cifrado
            ).decode("utf-8")

            resultado["mensaje_descifrado"] = descifrado.decode("utf-8")
            resultado["estado"] = "Cifrado y descifrado exitosos."

        elif accion == "firmar":
            firma = clave_privada.sign(
                mensaje.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            clave_publica.verify(
                firma,
                mensaje.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            resultado["firma"] = base64.b64encode(firma).decode("utf-8")
            resultado["estado"] = "Firma digital verificada correctamente."
            
        elif accion == "ataque":
            mensaje_original = mensaje.encode("utf-8")

            # Firmar el mensaje original con la clave privada
            firma = clave_privada.sign(
                mensaje_original,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Simular que un atacante modifica el mensaje
            mensaje_alterado = (
                mensaje + " [MENSAJE ALTERADO]"
            ).encode("utf-8")

            # Intentar verificar la firma con el mensaje alterado
            try:
                clave_publica.verify(
                    firma,
                    mensaje_alterado,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                resultado["ataque"] = (
                    "La firma fue aceptada inesperadamente."
                )

            except InvalidSignature:
                resultado["ataque"] = (
                    "ATAQUE DETECTADO: la firma digital es inválida."
                )

            resultado["mensaje_original"] = mensaje
            resultado["mensaje_alterado"] = (
                mensaje + " [MENSAJE ALTERADO]"
            )
            resultado["firma"] = base64.b64encode(
                firma
            ).decode("utf-8")
            resultado["estado"] = (
                "La modificación del mensaje fue detectada."
            )


        else:
            raise ValueError("Selecciona una operación válida.")

        # Mostrar únicamente la clave pública en formato PEM
        resultado["clave_publica"] = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    except (ValueError, InvalidSignature, binascii.Error) as error:
        resultado["error"] = str(error) or "No fue posible completar la operación."

    except Exception:
        resultado["error"] = "Ocurrió un error al procesar la operación."

    return render_template(
        "index.html",
        resultado=resultado,
        mensaje=mensaje
    )

def ejecutar_pruebas():
    pruebas = []

    mensaje = "Prueba de seguridad RSA para CRIPTOSEGURIDAD."
    datos = mensaje.encode("utf-8")

    clave_privada = None
    clave_publica = None
    mensaje_recuperado = None
    firma = None

    def registrar(codigo, nombre, aprobado, detalle):
        pruebas.append({
            "codigo": codigo,
            "nombre": nombre,
            "estado": "APROBADA" if aprobado else "FALLIDA",
            "aprobada": aprobado,
            "detalle": detalle
        })

    # PF-01: Generación de claves
    try:
        clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        clave_publica = clave_privada.public_key()

        registrar(
            "PF-01",
            "Generación de claves RSA",
            True,
            "Se generó un par de claves RSA de 2048 bits."
        )
    except Exception:
        registrar(
            "PF-01",
            "Generación de claves RSA",
            False,
            "No fue posible generar el par de claves."
        )

    # PF-02: Cifrado
    cifrado = None
    try:
        if clave_publica is None:
            raise ValueError("No hay clave pública disponible.")

        cifrado = clave_publica.encrypt(
            datos,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        registrar(
            "PF-02",
            "Cifrado de información",
            True,
            "El mensaje fue cifrado con la clave pública."
        )
    except Exception:
        registrar(
            "PF-02",
            "Cifrado de información",
            False,
            "No fue posible cifrar el mensaje."
        )

    # PF-03: Descifrado
    try:
        if clave_privada is None or cifrado is None:
            raise ValueError("Faltan datos para descifrar.")

        mensaje_recuperado = clave_privada.decrypt(
            cifrado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        registrar(
            "PF-03",
            "Descifrado de información",
            True,
            "El mensaje fue descifrado con la clave privada."
        )
    except Exception:
        registrar(
            "PF-03",
            "Descifrado de información",
            False,
            "No fue posible descifrar el mensaje."
        )

    # PF-04: Verificación de firma
    try:
        if clave_privada is None or clave_publica is None:
            raise ValueError("No hay claves disponibles.")

        firma = clave_privada.sign(
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        clave_publica.verify(
            firma,
            datos,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        registrar(
            "PF-04",
            "Verificación de firma digital",
            True,
            "La firma original fue verificada correctamente."
        )
    except Exception:
        registrar(
            "PF-04",
            "Verificación de firma digital",
            False,
            "No fue posible verificar la firma original."
        )

    # PF-05: Detección de alteración
    try:
        if clave_publica is None or firma is None:
            raise ValueError("No hay firma disponible.")

        mensaje_alterado = datos + b" MENSAJE MODIFICADO"

        try:
            clave_publica.verify(
                firma,
                mensaje_alterado,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            ataque_detectado = False
        except InvalidSignature:
            ataque_detectado = True

        registrar(
            "PF-05",
            "Detección de alteración",
            ataque_detectado,
            "La modificación fue detectada por la verificación de firma."
            if ataque_detectado else
            "La firma aceptó inesperadamente el mensaje alterado."
        )
    except Exception:
        registrar(
            "PF-05",
            "Detección de alteración",
            False,
            "No fue posible ejecutar la prueba de alteración."
        )

    # PF-06: Recuperación del mensaje original
    recuperado_correctamente = (
        mensaje_recuperado == datos
        if mensaje_recuperado is not None else False
    )

    registrar(
        "PF-06",
        "Recuperación del mensaje original",
        recuperado_correctamente,
        "El mensaje recuperado coincide con el original."
        if recuperado_correctamente else
        "El mensaje recuperado no coincide con el original."
    )

    return pruebas


@app.route("/pruebas")
def panel_pruebas():
    pruebas = ejecutar_pruebas()
    aprobadas = sum(1 for prueba in pruebas if prueba["aprobada"])

    return render_template(
        "index.html",
        pruebas=pruebas,
        total_pruebas=len(pruebas),
        pruebas_aprobadas=aprobadas
    )



@app.errorhandler(404)
def pagina_no_encontrada(error):
    return "Error 404: Página no encontrada", 404


@app.errorhandler(500)
def error_servidor(error):
    return "Se presentó un error interno del servidor.", 500


if __name__ == "__main__":
    app.run(debug=True)
