from GC import ot
from GC import yao
from GC import util
from abc import ABC, abstractmethod
import logging
import time
import base64
import os
from python_snarks import Groth, Calculator, gen_proof, is_valid
from zkpy.ptau import PTau
from zkpy.circuit import Circuit, GROTH, PLONK, FFLONK


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
        alice_start = time.time()
        super().__init__(circuits)
        alice_end = time.time()
        print(f"Garble time: {alice_end - alice_start}")
        send_start = time.time()
        self.socket = util.GarblerSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)
        print(f"Send time: {time.time() - send_start}")
        print(f"OT enabled: {oblivious_transfer}")

    def start(self):
        """Start Yao protocol."""
        for circuit in self.circuits:
            to_send = {
                "circuit": circuit["circuit"],
                "garbled_tables": circuit["garbled_tables"],
                "pbits_out": circuit["pbits_out"],
            }
            logging.debug(f"Sending {circuit['circuit']['id']}")
            self.socket.send_wait_to_evaluator(to_send)
            self.print(circuit)

    def print(self, entry):
        """Print circuit evaluation for all Bob and Alice inputs.

        Args:
            entry: A dict representing the circuit to evaluate.
        """
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        print(f"gates_num: {len(circuit['gates'])}")
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
        print(f"b_keys: {b_keys}")
        print(f"b_bytes_keys: {b_bytes_keys}")
        print(f"b_decode_keys: {b_decode_keys}")

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

            print(f"  Alice{a_wires} = {str_bits_a} "
                  f"Bob{b_wires} = {str_bits_b}  "
                  f"Outputs{outputs} = {str_result}")

        print()

    def _get_encr_bits(self, pbit, key0, key1):
        return ((key0, 0 ^ pbit), (key1, 1 ^ pbit))
    

    def listen(self):
        """Listen for incoming requests and send b_decode_keys to user."""
        while True:
            # Wait for incoming request
            message = self.socket.receive()
            print("Received request:", message)
            
            # Assume message contains the necessary information to identify the circuit
            circuit_id = message.get("circuit_id")
            for circuit in self.circuits:
                if circuit["circuit"]["id"] == circuit_id:
                    # Generate b_decode_keys for the requested circuit
                    pbits, keys = circuit["pbits"], circuit["keys"]
                    b_wires = circuit["circuit"].get("bob", [])
                    b_decode_keys = {
                        w: self._get_encr_bits(pbits[w], 
                                               int.from_bytes(base64.urlsafe_b64decode(keys[w][0]), byteorder='big'), 
                                               int.from_bytes(base64.urlsafe_b64decode(keys[w][1]), byteorder='big'))
                        for w in b_wires
                    }
                    # Send b_decode_keys to user
                    self.socket.send(b_decode_keys)
                    print("Sent b_decode_keys:", b_decode_keys)
                    break

class AccessController:

    def __init__(self, oblivious_transfer=False):
        self.socket = util.EvaluatorSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)

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
        circuit, pbits_out = entry["circuit"], entry["pbits_out"]
        garbled_tables = entry["garbled_tables"]
        a_wires = circuit.get("alice", [])  # list of Alice's wires
        b_wires = circuit.get("bob", [])  # list of Bob's wires
        print(f"Bobs wires: {b_wires}")
        N = len(a_wires) + len(b_wires)

        print(f"Received {circuit['id']}")
        print(f"circuit: {circuit}")

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

class User:
    def __init__(self):
        self.socket = util.UserSocket()
    
    def request_b_decode_keys(self, circuit_id):
        request = {"circuit_id": circuit_id}
        print("Sending request:", request)
        self.socket.send(request)
        
        response = self.socket.receive()
        print("Received b_decode_keys:", response)
        return response
    
    def start(self):
        labels = self.request_b_decode_keys("Smart")
        
        ptau = PTau()
        ptau.start() 
        ptau.contribute()
        ptau.beacon()
        ptau.prep_phase2()
        ptau.verify()


        # print("1. setting up...")
        # gr = Groth(os.path.dirname(os.path.realpath(__file__)) + "/ZK/test-vectors/simple-test/commit_ped.r1cs")
        # gr.setup_zk()

        # ## 2. proving
        # print("2. proving...")
        # wasm_path = os.path.dirname(os.path.realpath(__file__)) + "/ZK/test-vectors/simple-test/commit_ped_js/commit_ped.wasm"
        # c = Calculator(wasm_path)
        # witness = c.calculate({"attr1": 1, "attr2": 0, "key1_0": labels[3][0][0], "key1_1": 0, "key2_0": 1, "key2_1": 0})
        # proof, publicSignals = gen_proof(gr.setup["vk_proof"], witness)
        # print("#"*80)
        # print(proof)
        # print("#"*80)
        # print(publicSignals)
        # print("#"*80)

        # ## 3. verifying
        # print("3. verifying...")
        # result = is_valid(gr.setup["vk_verifier"], proof, publicSignals)
        # print(result)
        # assert result == True
    

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