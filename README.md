# portmap

Fast local service discovery tool that scans and labels open ports with process context.

---

## Installation

```bash
pip install portmap
```

Or install from source:

```bash
git clone https://github.com/yourname/portmap.git && cd portmap && pip install .
```

---

## Usage

Run a full scan of open ports on the local machine:

```bash
portmap scan
```

Filter by port range:

```bash
portmap scan --range 3000-9000
```

Output includes the port number, protocol, process name, and PID:

```
PORT     PROTO    PID      PROCESS
22       TCP      1024     sshd
5432     TCP      3891     postgres
8080     TCP      12044    node
8888     TCP      9301     jupyter
```

Use as a Python library:

```python
from portmap import scanner

results = scanner.scan(port_range=(1024, 65535))
for entry in results:
    print(entry.port, entry.process_name, entry.pid)
```

---

## Requirements

- Python 3.8+
- Linux, macOS, or Windows
- [`psutil`](https://github.com/giampaolo/psutil)

---

## License

MIT © 2024 yourname