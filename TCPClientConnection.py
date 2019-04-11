import socket

target_host = "www.google.com"
target_port = 80

# create socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect client
client.connect((target_host, target_port))

# send a get request
client.send("GET / HTTP/1.1/\r\nHost:google.com\r\n\r\n")

# receive on designated port
response = client.recv(4096)

print response
