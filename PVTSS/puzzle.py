import os
import sys
import timeit
import time
import subprocess
from pvss import Pvss
from pvss.ristretto_255 import create_ristretto_255_parameters

from .algorithms.fast_exponentiation import fast_exponentiation

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


def encrypt(message: bytes, seconds: int, squarings_per_second: int):
    if not seconds or not squarings_per_second:
        raise AssertionError

    # hard code safe exponent to use
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # see RSA for security specifications
    p, q = private_key.private_numbers().p, private_key.private_numbers().q
    n = private_key.public_key().public_numbers().n
    phi_n = (p - 1) * (q - 1)

    # Fernet is an asymmetric encryption protocol using AES
    key = Fernet.generate_key()
    key_int = int.from_bytes(key, sys.byteorder)
    cipher_suite = Fernet(key)

    # Vote Encryption
    encrypted_message = cipher_suite.encrypt(message)

    # Pick safe, pseudo-random a where 1 < a < n
    # Alternatively, we could use a = 2
    a = int.from_bytes(os.urandom(32), sys.byteorder) % n + 1

    # Key Encryption
    t = seconds * squarings_per_second
    e = 2**t % phi_n
    b = fast_exponentiation(n, a, e)

    encrypted_key = (key_int % n + b) % n
    return p, q, n, a, t, encrypted_key, encrypted_message, key_int


def decrypt(n: int, a: int, t: int, enc_key: int, enc_message: int) -> bytes:
    # Successive squaring to find b
    # We assume this cannot be parallelized
    b = a % n
    for i in range(t):
        b = b**2 % n
    dec_key = (enc_key - b) % n

    # Retrieve key, decrypt message
    key_bytes = int.to_bytes(dec_key, length=64, byteorder=sys.byteorder)
    cipher_suite = Fernet(key_bytes)
    return cipher_suite.decrypt(enc_message)


if __name__ == '__main__':
    # We use the main function to time the accuracy of the decrypt function
    # Import the methods to use as-is
    if len(sys.argv) != 4:
        print('Please provide t, s')
    arg_t, arg_s, arg_repeats = sys.argv[1], sys.argv[2], sys.argv[3]
    print("t =", arg_t)
    print("s =", arg_s)

    init_start = time.time()
    # init, genparams
    pvss_init = Pvss()
    params = create_ristretto_255_parameters(pvss_init)
    print('Init time:', time.time() - init_start)

    alice_start = time.time()
    # alice, genuser
    pvss_alice = Pvss()
    pvss_alice.set_params(params)
    alice_priv, alice_pub = pvss_alice.create_user_keypair("Alice")
    print('Alice time:', time.time() - alice_start)

    # boris, genuser
    pvss_boris = Pvss()
    pvss_boris.set_params(params)
    boris_priv, boris_pub = pvss_boris.create_user_keypair("Boris")

    # chris, genuser
    pvss_chris = Pvss()
    pvss_chris.set_params(params)
    chris_priv, chris_pub = pvss_chris.create_user_keypair("Chris")

    dealer_start = time.time()
    # dealer, splitsecret
    pvss_dealer = Pvss()
    pvss_dealer.set_params(params)
    pvss_dealer.add_user_public_key(chris_pub)
    pvss_dealer.add_user_public_key(alice_pub)
    pvss_dealer.add_user_public_key(boris_pub)
    secret0, shares = pvss_dealer.share_secret(2)
    print('Dealer time:', time.time() - dealer_start)

    pvss_receiver_time = time.time()
    # receiver, genreceiver
    pvss_receiver = Pvss()
    pvss_receiver.set_params(params)
    recv_priv, recv_pub = pvss_receiver.create_receiver_keypair("receiver")
    print('Receiver time:', time.time() - pvss_receiver_time)

#     init_command = '''mkdir test
# cd test
# pvss datadir genparams rst255 
# pvss datadir genuser Alice alice.key
# pvss datadir genuser Boris boris.key
# pvss datadir genuser Chris chris.key
# pvss datadir splitsecret 2 secret0.der'''
#     init_pvss = result = subprocess.run(init_command, shell=True, text=True, capture_output=True)

    print('Encrypting')
    start_enc = time.time()
    p, q, n, a, t, encrypted_key, encrypted_message, original_key = encrypt(
        "This is a vote for Myrto".encode(),
        int(arg_t),
        int(arg_s)
    )
    print('Encryption time:', time.time() - start_enc)

#     ver_command = '''pvss datadir genreceiver recv.key
# pvss datadir reencrypt boris.key 
# pvss datadir reencrypt alice.key '''
#     ver_pvss = result = subprocess.run(ver_command, shell=True, text=True, capture_output=True)

    print('Decrypting')
    start_dec = time.time()
    # TODO: make separate script for measuring this
    # time it provides an accurate timing function with disabled garbage collecting
    # https://docs.python.org/3/library/timeit.html
    print(timeit.repeat(
        'print(decrypt(n, a, t, encrypted_key, encrypted_message))',
        globals=globals(),
        repeat=int(arg_repeats),
        number=1)
    )

    # print('Decryption time:', time.time() - start_dec)
    # con_command = '''pvss datadir reconstruct recv.key secret1.der'''
    # con_pvss = result = subprocess.run(con_command, shell=True, text=True, capture_output=True)
    
    verify_start = time.time()
    # boris, reencrypt
    pvss_boris.add_user_public_key(alice_pub)
    pvss_boris.add_user_public_key(chris_pub)
    pvss_boris.set_shares(shares)
    pvss_boris.set_receiver_public_key(recv_pub)
    reenc_boris = pvss_boris.reencrypt_share(boris_priv)
    print('Verification time:', time.time() - verify_start)

    # alice, reencrypt
    pvss_alice.add_user_public_key(boris_pub)
    pvss_alice.add_user_public_key(chris_pub)
    pvss_alice.set_shares(shares)
    pvss_alice.set_receiver_public_key(recv_pub)
    reenc_alice = pvss_alice.reencrypt_share(alice_priv)

    recover_start = time.time()
    # receiver, reconstruct
    pvss_receiver.add_user_public_key(boris_pub)
    pvss_receiver.add_user_public_key(chris_pub)
    pvss_receiver.add_user_public_key(alice_pub)
    pvss_receiver.set_shares(shares)
    pvss_receiver.add_reencrypted_share(reenc_alice)
    pvss_receiver.add_reencrypted_share(reenc_boris)
    secret1 = pvss_receiver.reconstruct_secret(recv_priv)

    print(secret0 == secret1)
    print('Recovery time:', time.time() - recover_start)