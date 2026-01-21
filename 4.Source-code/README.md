# ArScan

## Installation

Clone the source code and run following commands in arscan directory:

```bash
rm -rf env
python3 -m venv env
source env/bin/activate
pip install --upgrade setuptools wheel
pip install -e .
```

### Install solc-select for selecting a Solidity compiler version

```bash
pip install solc-select
solc-select install 0.4.11
solc-select use 0.4.11
```

### List available detectors

```bash
arscan --list-detectors
```

### Analyze .sol files with ArScan

```bash
arscan test.sol
```