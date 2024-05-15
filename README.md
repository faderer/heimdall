# heimdall
This repository is a decentralized access control system for off-chain service supporting fair access and policy confidentiality.
## How to build
This project is built using Rust, Python and Circom in Linux system. The following instructions will guide you through the installation of the necessary dependencies.
### Installing dependency
On Debian (Bullseye / 11 and later) or Ubuntu (Eoan / 19.10 and later):
```bash
sudo apt update
sudo apt install build-essential libsodium23 python3-dev libgmp3-dev m4 nodejs npm
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
### Installing ZoKrates
To have ZoKrates available in your system, you can install ZoKrates:
```bash
curl -LSfs get.zokrat.es | sh
```
### Installing Python
Download [Python 3.7](https://www.python.org/downloads/) or higher
### Installing Python packages
Install pbc library
```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
sudo make install
```
Install Charm-Crypto
```bash
git clone https://github.com/JHUISI/charm.git
cd charm
./configure.sh
make
sudo make install
python setup.py install --user
```
### Installing ganache-cli
```bash
sudo npm install -g ganache-cli
```
### Build heimdall
```bash
git clone https://github.com/faderer/heimdall.git
cd heimdall
pip install -r requirements.txt
cd zk
cargo build --release
cd ..
cd secret-nft
python secret_nft/compile_zk.py
pytest -s
```
