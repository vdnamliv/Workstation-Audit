# VT-Agent Distribution Package

##  Files included:
- `agent.exe` - VT-Agent executable
- `agent.conf` - Configuration file
- `windows.yml` - Windows compliance rules (reference)

##  Installation Instructions:

### 1. Copy files to target directory:
```cmd
# Example: C:\Program Files\VT-Agent\
mkdir "C:\Program Files\VT-Agent"
copy agent.exe "C:\Program Files\VT-Agent\"
copy agent.conf "C:\Program Files\VT-Agent\"
```

### 2. Install as Windows Service:
```cmd
# Run PowerShell as Administrator
sc.exe create VT-Agent binPath= "C:\Program Files\VT-Agent\agent.exe --service --skip-mtls" start= auto DisplayName= "VT Compliance Agent"
sc.exe start VT-Agent
```

### 3. Verify Installation:
```cmd
sc.exe query VT-Agent
```

##  Configuration:
Edit `agent.conf` to update server settings:
- `SERVER_URL` - VT-Server endpoint
- `BOOTSTRAP_TOKEN` - Authentication token

##  Management Commands:
```cmd
# Start service
sc.exe start VT-Agent

# Stop service
sc.exe stop VT-Agent

# Remove service
sc.exe stop VT-Agent
sc.exe delete VT-Agent
```

##  Features:
-  Server-controlled polling intervals
-  Automatic health checks
-  Policy caching & smart updates
-  Graceful server disconnect handling
-  Centralized audit result storage
