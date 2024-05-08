use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use std::time::SystemTime;
use num_bigint::{BigInt, Sign};

type GrothBn = Groth16<Bn254>;

#[test]
fn groth16_proof() -> Result<()> {
    let start_prove = SystemTime::now();
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/simple-test/commit_ped_js/commit_ped.wasm",
        "./test-vectors/simple-test/commit_ped.r1cs",
    )?;
    println!("config time: {:?}", start_prove.elapsed().unwrap());
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("attr1", 1);
    builder.push_input("attr2", 0);
    let byte_vector1_0: Vec<u8> = vec![88, 150, 76, 70, 100, 34, 10, 4, 70, 157, 105, 243, 135, 113, 9, 244, 20, 196, 154, 169, 226, 94, 152, 59, 153, 14, 67, 122, 125, 145, 176, 134];
    let byte_vector1_1: Vec<u8> = vec![19, 33, 32, 238, 76, 23, 11, 4, 240, 2, 77, 59, 226, 179, 109, 96, 100, 191, 105, 86, 61, 122, 26, 41, 136, 210, 159, 135, 170, 247, 76, 228];
    let byte_vector2_0: Vec<u8> = vec![60, 174, 53, 110, 198, 40, 97, 211, 75, 202, 54, 2, 45, 205, 125, 254, 124, 37, 47, 36, 2, 48, 56, 10, 10, 84, 92, 225, 252, 74, 248, 253];
    let byte_vector2_1: Vec<u8> = vec![123, 107, 202, 223, 198, 4, 124, 197, 140, 42, 207, 190, 34, 228, 209, 205, 185, 174, 1, 187, 161, 235, 134, 142, 2, 90, 231, 11, 244, 88, 1, 114];
    let byte_slice1_0: &[u8] = &byte_vector1_0[..];
    let byte_slice1_1: &[u8] = &byte_vector1_1[..];
    let byte_slice2_0: &[u8] = &byte_vector2_0[..];
    let byte_slice2_1: &[u8] = &byte_vector2_1[..];
    builder.push_input("key1_0", BigInt::from_bytes_be(Sign::Plus, byte_slice1_0));
    builder.push_input("key1_1", BigInt::from_bytes_be(Sign::Plus, byte_slice1_1));
    builder.push_input("key2_0", BigInt::from_bytes_be(Sign::Plus, byte_slice2_0));
    builder.push_input("key2_1", BigInt::from_bytes_be(Sign::Plus, byte_slice2_1));
    println!("push input time: {:?}", start_prove.elapsed().unwrap());
    

    // create an empty instance for setting it up
    let circom = builder.setup();
    println!("setup time: {:?}", start_prove.elapsed().unwrap());

    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;
    println!("build time: {:?}", start_prove.elapsed().unwrap());

    let inputs = circom.get_public_inputs().unwrap();
    println!("inputs: {:?}", inputs);

    let proof = GrothBn::prove(&params, circom, &mut rng)?;
    println!("prove time: {:?}", start_prove.elapsed().unwrap());

    let pvk = GrothBn::process_vk(&params.vk).unwrap();
    println!("proof time: {:?}", start_prove.elapsed().unwrap());

    let start_verify = SystemTime::now();
    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;
    println!("verify time: {:?}", start_verify.elapsed().unwrap());

    assert!(verified);

    Ok(())
}

#[test]
fn groth16_proof_wrong_input() {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    // This isn't a public input to the circuit, should fail
    builder.push_input("foo", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let _params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

    let _ = builder.build().unwrap_err();
}

#[test]
#[cfg(feature = "circom-2")]
fn groth16_proof_circom2() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/circom2_multiplier2.wasm",
        "./test-vectors/circom2_multiplier2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    let proof = GrothBn::prove(&params, circom, &mut rng)?;

    let pvk = GrothBn::process_vk(&params.vk).unwrap();

    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;

    assert!(verified);

    Ok(())
}

#[test]
#[cfg(feature = "circom-2")]
fn witness_generation_circom2() -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./test-vectors/circom2_multiplier2.wasm",
        "./test-vectors/circom2_multiplier2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 0x100000000u64 - 1);

    assert!(builder.build().is_ok());

    Ok(())
}
