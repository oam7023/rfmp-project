# RFMP - Remote File Management Protocol

A simple remote file/folder management protocol built with Python and C
sockets, for the Sockets with AI course project.

# Team
- Member 1 - Server core / protocol
- Member 2 - Security (RSA/AES/Caesar)
- Member 3 - Client + C client

# Files
- `server.py` - RFMP server (multithreaded, self-contained)
- `client.py` - RFMP Python client (self-contained)
- `client.c` - RFMP C client (openRead only, no encryption)

# Setup

pip install rsa


# Running

py server.py
py client.py


# Status
- [x] Setup Phase (SS / CC / EC handshake)
- [ ] Operation Phase (CM commands, openRead/openWrite, DP packets)
- [ ] Exception packets (EE)
- [ ] C client
