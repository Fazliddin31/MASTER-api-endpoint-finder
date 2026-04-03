#### Requirements
``` 
pip install requests
```
#### On kali
```
sudo apt install subfinder assetfinder
```
#### Another distros
```
go install github.com/tomnomnom/assetfinder@latest && sudo cp ~/go/bin/assetfinder /usr/bin
```
```
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && sudo cp ~/go/bin/subfinder /usr/bin
```

#### Basic
```
python3 recon.py <domain>
```

#### All flags
```
python3 recon.py <domain> --threads 15 --timeout 6 --delay 0.2
```

#### If assetfinder/subfinder aren't installed
```
python3 recon.py <domain> --skip-tools
```
