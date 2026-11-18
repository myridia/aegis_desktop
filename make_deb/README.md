## Debian package

## Build
```
cd src
dpkg-buildpackage -us -uc -b
```

## Install with apt (pulls in dependencies)
```
apt install ./aegis-desktop_1.0.0-1_amd64.deb
```

## Install with dpkg
```
sudo dpkg -i aegis-desktop_1.0.0-1_amd64.deb
```

## Review installed files
```
dpkg -L aegis-desktop
```

## Remove
```
sudo apt-get remove aegis-desktop --purge
```
