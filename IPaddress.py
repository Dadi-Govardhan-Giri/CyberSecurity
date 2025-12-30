import socket

# Get the hostname
hostname = socket.gethostname()

# Get the local IP address
local_ip = socket.gethostbyname(hostname)

print("Hostname:", hostname)
print("Local IP Address:", local_ip)
