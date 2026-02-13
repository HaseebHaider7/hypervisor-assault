# Hypervisor Assault

Hypervisor discovery and fingerprinting tool for educational use and authorized security testing.

## Legal Disclaimer
Educational purposes and authorized testing only. Scan only systems you own or where you have explicit written permission.

## Quick Start
```bash
cd hypervisor-assault
chmod +x scripts/hypervisor-assault.sh
sudo ./scripts/hypervisor-assault.sh
```

When run without arguments, it prompts:
1. Target IP
2. Target File
3. Quit

## Target File Example
See `examples/targets.txt`.

## Output
Each run creates a folder like `hypervisor_assault_YYYYMMDD_HHMMSS/` with:
- `01_targets_expanded.txt`
- `02_open_ports.txt`
- `03_fingerprints.txt`
- `assault.log`

## Dependencies
- `nmap`, `curl`, `dnsutils` (`dig`), `python3`
- Optional: `masscan` (if present, script will try to use it and will require `sudo`)

## License
MIT (see `LICENSE`).
