import socket

def main():

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_addr = ('127.0.0.1', 69)
    send_data = '\x00\x01\x73\x74\x75\x76\x00'


    udp_socket.sendto(send_data, send_addr)   
    udp_socket.sendto(send_data, send_addr)   
    udp_socket.close()

if __name__ == '__main__':
    main()
