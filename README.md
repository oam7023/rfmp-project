# RFMP - Remote File Management Protocol

A simple remote file/folder management protocol built with Python and C
sockets.

# Team
- Member 1 - Server/Client setup core
- Member 2 - Operation phase 
- Member 3 - C client

# Files
- `server.py` - RFMP server (multithreaded)
- `client.py` - RFMP Python client
- `client.c` - RFMP C client (openRead only, no encryption)

# Setup

pip install rsa


# Running

py server.py
py client.py


# Status
- [x] Setup Phase (SS / CC / EC handshake)
- [x] Operation Phase (CM commands, openRead/openWrite, DP packets)
- [x] Exception packets (EE)
- [x] C client
