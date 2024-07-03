# heimdall
This repository is a decentralized access control system for off-chain service supporting fair access and policy confidentiality.
## Structure
- `GC` contains the garbled circuit module.
    - `yao` contains the yao's garbled circuit implementation.
    - `ot` contains the oblivious transfer implementation.
    - `utils` contains the utility functions for socket communication and prime calculation.
- `circuits` contains the garbled circuits.
- `PVTSS` contains the pvss and tlp module.
- `ZK` contains the zero-knowledge proof circuit.
- `VE` contains the verifiable encryption module.
- `FE` contains the functional encryption module.
- `JWT` contains the JSON Web Token module.
- `data` contains the plaintext and ciphertext data owned by the service provider.
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
```bash
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```
### Installing ZoKrates
```bash
curl -LSfs get.zokrat.es | sh
```
### Installing snarkjs
```bash
npm install -g snarkjs
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
### Installing ipfs
```bash
wget https://dist.ipfs.tech/go-ipfs/v0.7.0/go-ipfs_v0.7.0_linux-amd64.tar.gz
tar -xvzf go-ipfs_v0.7.0_linux-amd64.tar.gz
cd go-ipfs
sudo bash install.sh
chmod +x /usr/local/bin/ipfs
ipfs init
ipfs daemon
```
### Build heimdall
```bash
git clone https://github.com/faderer/heimdall.git
cd heimdall
pip install -r requirements.txt
cd ZK
cargo build --release
cd ..
cd VE
python secret_nft/compile_zk.py
```
## Usage
### Running the tests
1. By default all tests are done on the local network. You can edit the network informations in `GC/utils.py`.
2. Start the IPFS daemon: `ipfs daemon`.
3. Run the access controller (Bob): `make bob`.
4. In another terminal, run the service provider (Alice): `python3 main.py alice -c <circuit.json>`.
5. In another terminal, run the client (Carol): `make carol`.
### The workflow
First, Alice will send the encrypted data to the IPFS network and send the garbled circuit to Bob. Then, Alice will split the secret key and send them to Bob. Upon recieving the request from Carol, Alice will send the labels information to Carol. After recieving the labels information, Carol will send the encoded input to Bob with zero-knowledge proof. Bob will then verify the zero-knowledge proof, evaluate the garbled circuit and send the secret shares to Carol. Carol will then reconstruct the secret key and decrypt the data downloaded from IPFS.