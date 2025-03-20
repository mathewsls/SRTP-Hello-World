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

# Mensaje "Hello World" como paquete RTP
mensaje = b"Hello World"
paquete_rtp = b'\x80\x60\x00\x01' + mensaje  # Encabezado RTP + mensaje
paquete_srtp = session.protect(paquete_rtp)

# Enviar el paquete SRTP
sock.sendto(paquete_srtp, ('localhost', 5000))
print("Mensaje enviado al servidor")

# Recibir respuesta del servidor
data, addr = sock.recvfrom(1024)
print("Respuesta recibida del servidor", addr)

# Desproteger la respuesta SRTP
respuesta_desprotegida = session.unprotect(data)
print("Respuesta desprotegida:", respuesta_desprotegida)