## Snort

```bash
  sudo apt install snort

```

```bash
  sudo chmod +x configure_snort_interface.sh
  ./configure_snort_interface.sh
```

```bash
sudo mv snort.conf /etc/snort/
sudo mv project.rules /etc/snort/rules/
```

```bash
sudo snort -i s1-snort -c /etc/snort/snort.conf
```
