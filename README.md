#### Requirements
``` 
pip install requests
```
```
go install github.com/tomnomnom/assetfinder@latest
```
```
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### Basic
```
python3 recon.py invest.miit.uz
```

#### All flags
```
python3 recon.py invest.miit.uz --threads 15 --timeout 6 --delay 0.2
```

#### If assetfinder/subfinder aren't installed
```
python3 recon.py invest.miit.uz --skip-tools
```
