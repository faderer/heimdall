# heimdall
This repository is a decentralized access control system for off-chain service supporting fair access and policy confidentiality.
## How to build
This project is built using Rust, Python and Circom in Linux system. The following instructions will guide you through the installation of the necessary dependencies.
### Installing dependency
On Debian (Bullseye / 11 and later) or Ubuntu (Eoan / 19.10 and later):
```bash
sudo apt update
sudo apt install build-essential
sudo apt install libsodium23
```
### Installing Rust and Cargo
To have Rust available in your system, you can install rustup. If you’re using Linux or macOS, open a terminal and enter the following command:
```bash
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```
### Installing Circom
To have circom available in your system, you can install circom:
```bash
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```
### Installing Python
Download [Python 3.7](https://www.python.org/downloads/) or higher
### Build heimdall
```bash
git clone https://github.com/faderer/heimdall.git
cd heimdall
pip install -r requirements.txt
cd zk
cargo build --release
```
