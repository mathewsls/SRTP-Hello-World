from pylibsrtp import Policy, Session
import socket

# Configuración de la política de seguridad SRTP
policy = Policy(
    key=b'\x00' * 30,  # Clave maestra para la protección SRTP
    srtp_profile=Policy.SRTP_PROFILE_AES128_CM_SHA1_80,  # Perfil de seguridad SRTP
    ssrc_type=Policy.SSRC_ANY_OUTBOUND,  # Tipo de SSRC
    ssrc_value=0x00000001  # Valor de SSRC
)

# Crear una sesión SRTP
session = Session(policy=policy)

# Crear un socket UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Enlazar el socket a la dirección y puerto
sock.bind(('localhost', 5000))

print("Servidor iniciado. Esperando mensajes...")

while True:
    # Recibir mensajes
    data, addr = sock.recvfrom(1024)
    print("Mensaje recibido de", addr)

    # Desproteger el mensaje SRTP
    mensaje_desprotegido = session.unprotect(data)
    print("Mensaje desprotegido:", mensaje_desprotegido)

    # Enviar respuesta
    respuesta = b"Mensaje recibido correctamente!"
    paquete_rtp = b'\x80\x60\x00\x01' + respuesta  # Encabezado RTP + respuesta
    paquete_srtp = session.protect(paquete_rtp)
    sock.sendto(paquete_srtp, addr)
    print("Respuesta enviada a", addr)