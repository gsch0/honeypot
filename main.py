import socket
import struct

HOST = '0.0.0.0'
PORT = 22 

def send_banner(client_socket):

    client_socket.send(b"SSH-2.0-Honeypot_SSH_Protocol\r\n")
    print("Bannière envoyée à la connexion.")


def send_kexinit(client_socket):
    """Envoie une réponse KEXINIT valide."""
    kexinit_payload = (
        b'\x00\x00\x01\xc4'  # Longueur totale du paquet (y compris padding et type) : 452 octets
        b'\x14'  # Type de paquet : KEXINIT
        + b'\x00' * 16  # Cookie : 16 octets aléatoires (ici simplifiés à 0)
        + b'diffie-hellman-group14-sha1,diffie-hellman-group1-sha1\x00'
        + b'rsa-sha2-256,rsa-sha2-512\x00'
        + b'chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr\x00'
        + b'chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr\x00'
        + b'umac-64-etm@openssh.com,umac-128-etm@openssh.com\x00'
        + b'umac-64-etm@openssh.com,umac-128-etm@openssh.com\x00'
        + b'none,zlib@openssh.com\x00'
        + b'none,zlib@openssh.com\x00'
        + b'\x00\x00\x00\x00'  # Premières clés KEX
    )
    
    client_socket.send(kexinit_payload)
    print("Paquet KEXINIT envoyé.\n\n")

    data = client_socket.recv(1024)
    print("Paramètres Diffie-Hellman du client reçus :")
    print(data)

    # Simuler une réponse avec les paramètres publics du serveur (f)
    server_dh_param = b"\x00" * 256  # Paramètres DH fictifs
    packet = b'\x00\x00\x01\x00' + server_dh_param  # Longueur + Paramètre
    client_socket.send(packet)
    print("\nRéponse DH envoyée au client.")

    # Attendre la confirmation du client
    data = client_socket.recv(1024)
    print("\nConfirmation du client :")
    print(data)

    chosen_algorithms = (
        b'\x00\x00\x00\x29' +  # Longueur totale (41 octets)
        b'hmac-sha2-256,none'  # Exemple d'algorithmes choisis
    )
    client_socket.send(chosen_algorithms)
    print("Algorithmes choisis envoyés au client.")



def handle_client(client_socket):
    """ Gère l'échange initial de paquets. """
    # Envoi de la version SSH du serveur
    send_banner(client_socket)

    # Attente de la demande d'initialisation (appelée "kexinit")
    data = client_socket.recv(1024)
    print(data)

    if data:
        send_kexinit(client_socket)
        
        

    client_socket.close()

def start_server():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Honeypot SSH en écoute sur {HOST}:{PORT}...")

    while True:
        # Acceptation d'une connexion client
        client_socket, client_addr = server_socket.accept()
        print(f"Connexion de {client_addr}")

        # Gérer la connexion du client dans un thread (ou directement ici, selon ta configuration)
        handle_client(client_socket)


if __name__ == "__main__":
    start_server()
