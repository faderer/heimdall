from GC import ot
from GC import yao
from GC import util
from PVTSS import puzzle
from pvss import Pvss
from pvss.ristretto_255 import create_ristretto_255_parameters
from abc import ABC, abstractmethod
import logging
import time
import ipfshttpclient
import requests
import base64
import os
import subprocess
import json
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
from mife.single.lwe import FeLWE



logging.basicConfig(format="[%(levelname)s] %(message)s",
                    level=logging.WARNING)

class YaoGarbler(ABC):
    """An abstract class for Yao garblers (e.g. Alice)."""
    def __init__(self, circuits):
        circuits = util.parse_json(circuits)
        self.name = circuits["name"]
        self.circuits = []

        for circuit in circuits["circuits"]:
            garbled_circuit = yao.GarbledCircuit(circuit)
            pbits = garbled_circuit.get_pbits()
            entry = {
                "circuit": circuit,
                "garbled_circuit": garbled_circuit,
                "garbled_tables": garbled_circuit.get_garbled_tables(),
                "keys": garbled_circuit.get_keys(),
                "pbits": pbits,
                "pbits_out": {w: pbits[w]
                              for w in circuit["out"]},
            }
            self.circuits.append(entry)

    @abstractmethod
    def start(self):
        pass

class ServiceProvider(YaoGarbler):
    def __init__(self, circuits, oblivious_transfer=False):
        super().__init__(circuits)
        self.socket = util.GarblerSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)
        self.init_dealer()

    def init_dealer(self):
        pvss_init = Pvss()
        self.params = create_ristretto_255_parameters(pvss_init)
        self.pvss_dealer = Pvss()
        self.pvss_dealer.set_params(self.params)
        self.secend = 100
        self.squarings_per_second = 10000
        self.message = "This is a vote for Myrto".encode()

    def update_dealer(self):
        result = self.socket.send_wait_to_evaluator(True)
        self.alice_pub = result["alice_pub"]
        self.boris_pub = result["boris_pub"]
        self.chris_pub = result["chris_pub"]
        self.pvss_dealer.add_user_public_key(self.chris_pub)
        self.pvss_dealer.add_user_public_key(self.alice_pub)
        self.pvss_dealer.add_user_public_key(self.boris_pub)
        self.secret0, self.shares = self.pvss_dealer.share_secret(2)
        to_send = {
            "shares": self.shares,
        }
        self.socket.send_wait_to_evaluator(to_send)
    
    def encrypt_file(self, file_path, key):
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + ciphertext)

        return encrypted_file_path
    
    def functional_encryption(self, x, y):
        # len(x) == len(y)
        n = len(x)
        key = FeLWE.generate(n, 4, 4)
        c = FeLWE.encrypt(x, key)
        sk = FeLWE.keygen(y, key)
        return c, sk

    
    def upload_to_ipfs(self, file_path):
        with open(file_path, 'rb') as file:
            client = ipfshttpclient.connect('/dns/localhost/tcp/5001/http')
            res = client.add(file_path)
            return res
    
    def to_32_bytes_hash(self, data):
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.digest()

    def start(self):
        """Start Yao protocol."""
        # secret0, shares = self.pvss_dealer.share_secret(2) # put inside
        # print(f"Shares: {shares}")
        for circuit in self.circuits:
            p, q, n, a, t, encrypted_key, encrypted_message, original_key = puzzle.encrypt(
                self.message,
                self.secend,
                self.squarings_per_second
            )
            print("1.Encrypt the puzzle")
            to_send = {
                "source": "garbler",
                "circuit": circuit["circuit"],
                "garbled_tables": circuit["garbled_tables"],
                "pbits_out": circuit["pbits_out"],
                "params": self.params,
                "n": n,
                "a": a,
                "t": t,
                "encrypted_key": encrypted_key,
                "encrypted_message": encrypted_message,
                # "shares": shares,
            }
            logging.debug(f"Sending {circuit['circuit']['id']}")
            self.socket.send_wait_to_evaluator(to_send)
            print("2.Garble the circuit")
            self.update_dealer()
            print("3.Split the secret")
            file_path = "data/financial_info.txt"
            key = self.to_32_bytes_hash(self.secret0)
            encrypted_file_path = self.encrypt_file(file_path, key)
            ipfs_hash = self.upload_to_ipfs(encrypted_file_path)
            self.cid = ipfs_hash['Hash']
            print("4.Encrypt the data and send the ciphertext to IPFS")
            x = [i for i in range(10)]
            y = [1/n for i in range(10)]
            c, sk = self.functional_encryption(x, y)
            self.print(circuit)

    def print(self, entry):
        """Print circuit evaluation for all Bob and Alice inputs.

        Args:
            entry: A dict representing the circuit to evaluate.
        """
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_keys = {  # map from Bob's wires to a pair (key, encr_bit)
            w: self._get_encr_bits(pbits[w], key0, key1)
            for w, (key0, key1) in keys.items() if w in b_wires
        }
        b_bytes_keys = {
            w: self._get_encr_bits(pbits[w], 
                                   list(base64.urlsafe_b64decode(key0)), 
                                   list(base64.urlsafe_b64decode(key1)))
            for w, (key0, key1) in keys.items() if w in b_wires
        }
        b_decode_keys = {
            w: self._get_encr_bits(pbits[w], 
                                   int.from_bytes(base64.urlsafe_b64decode(key0), byteorder='big'), 
                                   int.from_bytes(base64.urlsafe_b64decode(key1), byteorder='big'))
            for w, (key0, key1) in keys.items() if w in b_wires
        }

        # wire numbers of input
        N = len(a_wires) + len(b_wires)

        print(f"======== {circuit['id']} ========")

        # Generate all inputs for both Alice and Bob
        for bits in [format(n, 'b').zfill(N) for n in range(2**N)]:
            bits_a = [int(b) for b in bits[:len(a_wires)]]  # Alice's inputs

            # Map Alice's wires to (key, encr_bit)
            for i in range(len(a_wires)):
                a_inputs[a_wires[i]] = (keys[a_wires[i]][bits_a[i]],
                                        pbits[a_wires[i]] ^ bits_a[i])

            # Send Alice's encrypted inputs and keys to Bob
            result = self.ot.get_result(a_inputs, b_keys)

            # Format output
            str_bits_a = ' '.join(bits[:len(a_wires)])
            str_bits_b = ' '.join(bits[len(a_wires):])
            str_result = ' '.join([str(result[w]) for w in outputs])

            # print(f"  Alice{a_wires} = {str_bits_a} "
            #       f"Bob{b_wires} = {str_bits_b}  "
            #       f"Outputs{outputs} = {str_result}")

        print()

    def _get_encr_bits(self, pbit, key0, key1):
        return ((key0, 0 ^ pbit), (key1, 1 ^ pbit))
    

    def listen(self):
        """Listen for incoming requests and send b_decode_keys to user."""
        while True:
            # Wait for incoming request
            message = self.socket.receive()
            
            # Assume message contains the necessary information to identify the circuit
            circuit_id = message.get("circuit_id")
            for circuit in self.circuits:
                if circuit["circuit"]["id"] == circuit_id:
                    # Generate b_decode_keys for the requested circuit
                    pbits, keys = circuit["pbits"], circuit["keys"]
                    b_wires = circuit["circuit"].get("bob", [])
                    b_keys = {  # map from Bob's wires to a pair (key, encr_bit)
                        w: self._get_encr_bits(pbits[w], key0, key1)
                        for w, (key0, key1) in keys.items() if w in b_wires
                    }
                    b_decode_keys = {
                        w: self._get_encr_bits(pbits[w], 
                                               int.from_bytes(base64.urlsafe_b64decode(keys[w][0]), byteorder='big'), 
                                               int.from_bytes(base64.urlsafe_b64decode(keys[w][1]), byteorder='big'))
                        for w in b_wires
                    }
                    # Send b_decode_keys to user
                    to_send = {
                        "b_decode_keys": b_decode_keys,
                        "params": self.params,
                        "alice_pub": self.alice_pub,
                        "boris_pub": self.boris_pub,
                        "chris_pub": self.chris_pub,
                        "shares": self.shares,
                        "cid": self.cid,
                    }
                    self.socket.send(to_send)
                    break

class AccessController:

    def __init__(self, oblivious_transfer=False):
        self.socket = util.EvaluatorSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)
        # self.pvss_alice = pvss_alice
        # self.pvss_boris = pvss_boris
        # self.pvss_chris = pvss_chris
        # self.alice_priv = alice_priv
        # self.boris_priv = boris_priv
        # self.chris_priv = chris_priv
        # self.pvss_receiver = pvss_receiver
    
    def init_ac(self, params):
        self.pvss_alice = Pvss()
        self.pvss_alice.set_params(params)
        self.alice_priv, self.alice_pub = self.pvss_alice.create_user_keypair("Alice")

        # boris, genuser
        self.pvss_boris = Pvss()
        self.pvss_boris.set_params(params)
        self.boris_priv, self.boris_pub = self.pvss_boris.create_user_keypair("Boris")

        # chris, genuser
        self.pvss_chris = Pvss()
        self.pvss_chris.set_params(params)
        self.chris_priv, self.chris_pub = self.pvss_chris.create_user_keypair("Chris")
        
        self.socket.receive()
        to_send = {
            "alice_pub": self.alice_pub,
            "boris_pub": self.boris_pub,
            "chris_pub": self.chris_pub,
        }
        self.socket.send(to_send)
        result = self.socket.receive()
        self.shares = result["shares"]
        self.pvss_alice.add_user_public_key(self.chris_pub)
        self.pvss_alice.add_user_public_key(self.boris_pub)
        self.pvss_alice.set_shares(self.shares)
        self.pvss_boris.add_user_public_key(self.alice_pub)
        self.pvss_boris.add_user_public_key(self.chris_pub)
        self.pvss_boris.set_shares(self.shares)

        self.socket.send(True)

    def listen(self):
        """Start listening for Alice messages."""
        logging.info("Start listening")
        try:
            for entry in self.socket.poll_socket():
                self.socket.send(True)
                self.send_evaluation(entry)
        except KeyboardInterrupt:
            logging.info("Stop listening")

    def send_evaluation(self, entry):
        """Evaluate yao circuit for all Bob and Alice's inputs and
        send back the results.

        Args:
            entry: A dict representing the circuit to evaluate.
        """
        if entry["source"] == "garbler":
            self.init_ac(entry["params"])
            circuit, pbits_out = entry["circuit"], entry["pbits_out"]
            garbled_tables = entry["garbled_tables"]
            a_wires = circuit.get("alice", [])  # list of Alice's wires
            b_wires = circuit.get("bob", [])  # list of Bob's wires
            N = len(a_wires) + len(b_wires)

            n = entry["n"]
            a = entry["a"]
            t = entry["t"]
            encrypted_key = entry["encrypted_key"]
            encrypted_message = entry["encrypted_message"]
            puzzle.decrypt(n, a, t, encrypted_key, encrypted_message)
            print("5.Time puzzle decrypted")
            # print(timeit.repeat(
            #     'print(puzzle.decrypt(n, a, t, encrypted_key, encrypted_message))',
            #     globals=globals(),
            #     repeat=1,
            #     number=1)
            # )

            # Generate all possible inputs for both Alice and Bob
            for bits in [format(n, 'b').zfill(N) for n in range(2**N)]:
                bits_b = [int(b) for b in bits[N - len(b_wires):]]  # Bob's inputs

                # Create dict mapping each wire of Bob to Bob's input
                b_inputs_clear = {
                    b_wires[i]: bits_b[i]
                    for i in range(len(b_wires))
                }

                # Evaluate and send result to Alice
                self.ot.send_result(circuit, garbled_tables, pbits_out,
                                    b_inputs_clear)
            # shares = entry["shares"]
            # print(f"Shares: {shares}")
            # self.pvss_boris.set_shares(shares)
            #######TODO
            # self.reenc_boris = self.pvss_boris.reencrypt_share(self.boris_priv)
            # # self.pvss_alice.set_shares(shares)
            # self.reenc_alice = self.pvss_alice.reencrypt_share(self.alice_priv)
            # self.pvss_receiver.add_reencrypted_share(self.reenc_alice)
            # self.pvss_receiver.add_reencrypted_share(self.reenc_boris)

        elif entry["source"] == "user":
            self.socket.receive()
            proof = entry["proof"]
            public = entry["public"]
            verification_key = entry["verification_key"]
            command9 = "snarkjs groth16 verify verification_key.json public.json proof.json"
            original_directory = os.getcwd()
            os.chdir(os.getcwd() + "/ZK/circuit")
            result = subprocess.run(command9, capture_output=True, shell=True, check=True)
            output = result.stdout.decode('utf-8')
            clean_output = re.sub(r'\x1b\[[0-9;]*m', '', output).strip()
            
            self.pvss_alice.set_receiver_public_key(entry["recv_pub"])
            self.pvss_boris.set_receiver_public_key(entry["recv_pub"])
            self.reenc_alice = self.pvss_alice.reencrypt_share(self.alice_priv)
            self.reenc_boris = self.pvss_boris.reencrypt_share(self.boris_priv)
            to_send = {
                "source": "evaluator",
                "reenc_alice": self.reenc_alice,
                "reenc_boris": self.reenc_boris,
            }
            if "snarkJS: OK" in clean_output:
                self.socket.send(to_send)
                print("7.Verification successful")
            else:
                print("7.Verification failed")
            os.chdir(original_directory)


class User:
    def __init__(self):
        self.socket = util.UserSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=False)

    def init_receiver(self, params, alice_pub, boris_pub, chris_pub, shares):
        self.pvss_receiver = Pvss()
        self.pvss_receiver.set_params(params)
        self.recv_priv, self.recv_pub = self.pvss_receiver.create_receiver_keypair("receiver")
        self.pvss_receiver.add_user_public_key(alice_pub)
        self.pvss_receiver.add_user_public_key(boris_pub)
        self.pvss_receiver.add_user_public_key(chris_pub)
        self.pvss_receiver.set_shares(shares)

    def download_from_ipfs(self, cid, output_path):
        client = ipfshttpclient.connect('/dns/localhost/tcp/5001/http')
        data = client.cat(cid)
        with open(output_path, 'wb') as file:
            file.write(data)
    
    def decrypt_file(self, encrypted_file_path, key):
        backend = default_backend()
        with open(encrypted_file_path, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        decrypted_file_path = encrypted_file_path.replace('.enc', '.dec')
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)

        return decrypted_file_path
    
    def to_32_bytes_hash(self, data):
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.digest()

    def request_b_decode_keys(self, circuit_id):
        request = {"circuit_id": circuit_id}
        self.socket.send_to_garbler(request)
        
        response = self.socket.receive_from_garbler()
        self.init_receiver(response["params"], response["alice_pub"], response["boris_pub"], response["chris_pub"], response["shares"])
        self.cid = response["cid"]
        return response["b_decode_keys"]
    
    def start(self):
        labels = self.request_b_decode_keys("Smart")
        data = {
            "attr1": 1,
            "attr2": 0,
            "key1_0": labels[3][0][0],
            "key1_1": labels[3][1][0],
            "key2_0": labels[4][0][0],
            "key2_1": labels[4][1][0],
        }
        with open("ZK/circuit/input.json", "w") as f:
            json.dump(data, f, indent=4)
        
        command1 = "snarkjs powersoftau new bn128 12 pot12_0000.ptau -v"
        command2 = "snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name=\"First contribution\" -v"
        command3 = "snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v"
        command4 = "snarkjs groth16 setup commit_ped.r1cs pot12_final.ptau commit_ped_0000.zkey"
        command5 = "snarkjs zkey contribute commit_ped_0000.zkey commit_ped_0001.zkey --name=\"1st Contributor Name\" -v"
        command6 = "snarkjs zkey export verificationkey commit_ped_0001.zkey verification_key.json"
        
        command7 = "snarkjs wtns calculate commit_ped.wasm input.json witness.wtns"
        command8 = "snarkjs groth16 prove commit_ped_0001.zkey witness.wtns proof.json public.json"
        command9 = "snarkjs groth16 verify verification_key.json public.json proof.json"

        original_directory = os.getcwd()
        os.chdir(os.getcwd() + "/ZK/circuit")
        # subprocess.run(command1, shell=True, check=True)
        # subprocess.run(command2, shell=True, check=True)
        # subprocess.run(command3, shell=True, check=True)
        # subprocess.run(command4, shell=True, check=True)
        # subprocess.run(command5, shell=True, check=True)
        # subprocess.run(command6, shell=True, check=True)
        subprocess.run(command7, shell=True, check=True)
        subprocess.run(command8, shell=True, check=True)
        os.chdir(original_directory)

        with open("ZK/circuit/proof.json", "r") as f:
            proof = json.load(f)
        with open("ZK/circuit/public.json", "r") as f:
            public = json.load(f)
        with open("ZK/circuit/verification_key.json", "r") as f:
            verification_key = json.load(f)
        
        to_send = {
            "source": "user",
            "proof": proof,
            "public": public,
            "verification_key": verification_key,
            "recv_pub": self.recv_pub,
        }
        print("6.Proof generated")

        # true = self.socket.receive_from_evaluator()
        self.socket.send_wait_to_evaluator(to_send)
        self.socket.send_to_evaluator(True)
        entry = self.socket.receive_from_evaluator()
        reenc_alice = entry["reenc_alice"]
        reenc_boris = entry["reenc_boris"]
        self.pvss_receiver.add_reencrypted_share(reenc_alice)
        self.pvss_receiver.add_reencrypted_share(reenc_boris)
        secret1 = self.pvss_receiver.reconstruct_secret(self.recv_priv)
        print("8.Secret recovered")
        self.download_from_ipfs(self.cid, "data/financial_info_down.txt.enc")
        key = self.to_32_bytes_hash(secret1)
        decrypted_file_path = self.decrypt_file("data/financial_info_down.txt.enc", key)
        print(f"9.Decrypted file: {decrypted_file_path}")

def main(
    party,
    circuit_path="circuits/default.json",
    oblivious_transfer=False,
    print_mode="circuit",
    loglevel=logging.WARNING,
):
    logging.getLogger().setLevel(loglevel)

    
    if party == "alice":
        alice = ServiceProvider(circuit_path, oblivious_transfer=False)
        alice.start()
        alice.listen()
    elif party == "bob":
        bob = AccessController(oblivious_transfer=False)
        bob.listen()
    elif party == "carol":
        carol = User()
        carol.start()
    elif party == "local":
        local = LocalTest(circuit_path, print_mode=print_mode)
        local.start()
    else:
        logging.error(f"Unknown party '{party}'")


if __name__ == '__main__':
    import argparse

    def init():
        loglevels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL
        }

        parser = argparse.ArgumentParser(description="Run Yao protocol.")
        parser.add_argument("party",
                            choices=["alice", "bob", "carol", "local"],
                            help="the yao party to run")
        parser.add_argument(
            "-c",
            "--circuit",
            metavar="circuit.json",
            default="circuits/default.json",
            help=("the JSON circuit file for alice and local tests"),
        )
        parser.add_argument("--no-oblivious-transfer",
                            action="store_true",
                            help="disable oblivious transfer")
        parser.add_argument(
            "-m",
            metavar="mode",
            choices=["circuit", "table"],
            default="circuit",
            help="the print mode for local tests (default 'circuit')")
        parser.add_argument("-l",
                            "--loglevel",
                            metavar="level",
                            choices=loglevels.keys(),
                            default="warning",
                            help="the log level (default 'warning')")

        main(
            party=parser.parse_args().party,
            circuit_path=parser.parse_args().circuit,
            oblivious_transfer=not parser.parse_args().no_oblivious_transfer,
            print_mode=parser.parse_args().m,
            loglevel=loglevels[parser.parse_args().loglevel],
        )

    init()