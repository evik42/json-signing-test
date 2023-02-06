use std::io::{BufWriter, Write};
use std::{fs, fs::File, path::PathBuf};
use std::ops::Deref;

use anyhow::Result;
use clap::{Args, Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

use GolemCertCli::*;

#[derive(Parser)]
enum GolemCertCli {
    Verify { signed_data_file: String },
    Sign(Sign),
}

#[derive(Args)]
struct Sign {
    json_file: String,
    signed_data_file: PathBuf,
    #[arg(long="hash")]
    hash_algorithm: Option<HashAlgorithm>,
}

#[derive(Deserialize, Serialize)]
struct SignedData<'a> {
    #[serde(borrow)]
    signed_data: &'a RawValue,
    signatures: Vec<Signature>,
}

#[derive(Serialize)]
struct SignedDataPrettify {
    signed_data: Value,
    signatures: Vec<Signature>,
}

#[derive(Deserialize, Serialize)]
struct Signature {
    algorithm: HashAlgorithm,
    signature_value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum HashAlgorithm {
    Sha256, Sha384, Sha512, Sha3_256, Sha3_384, Sha3_512
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        HashAlgorithm::Sha3_256
    }
}

fn main() -> Result<()> {
    let command = GolemCertCli::parse();
    match &command {
        Verify { signed_data_file } => verify(signed_data_file),
        Sign(parameters) => sign(parameters),
    }
}

fn sign(parameters: &Sign) -> Result<()> {
    let data = fs::read_to_string(&parameters.json_file)?;
    let parsed_json: Value = serde_json::from_str(&data)?;
    let prettify = SignedDataPrettify { signed_data: parsed_json, signatures: vec![] };
    let pretty_string = serde_json::to_string_pretty(&prettify)?;
    let mut signed_data: SignedData = serde_json::from_str(&pretty_string)?;

    let hash_algorithm = parameters.hash_algorithm.clone().unwrap_or_default();
    let hash = create_digest(signed_data.signed_data.get(), &hash_algorithm);
    let hash_string = hex::encode(&hash); // base64encoder::STANDARD_NO_PAD.encode(&hash);
    let signature = Signature { algorithm: hash_algorithm, signature_value: hash_string };
    signed_data.signatures.push(signature);
    {
        let mut writer = BufWriter::new(File::create(&parameters.signed_data_file)?);
        serde_json::to_writer_pretty(&mut writer, &signed_data)?;
        writer.write(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

fn verify(signed_data_file: &String) -> Result<()> {
    let signed_data_string = fs::read_to_string(signed_data_file)?;
    let signed_data: SignedData = serde_json::from_str(&signed_data_string)?;

    for (idx, signature) in signed_data.signatures.iter().enumerate() {
        let stored_hash = hex::decode(&signature.signature_value)?;
        let hash = create_digest(signed_data.signed_data.get(), &signature.algorithm);
        print!("Signature {} is ", idx);
        if stored_hash.as_slice() == hash.deref() {
            println!("valid");
        } else {
            println!("INVALID");
        }
    }
    Ok(())
}

fn create_digest(input: &str, hash_type: &HashAlgorithm) -> Vec<u8> {
    // Digest trait and the output hash contains the size so we cannot create a common variable prior to converting it into a Vec<u8>
    match hash_type {
        HashAlgorithm::Sha256 => Sha256::digest(input).into_iter().collect(),
        HashAlgorithm::Sha384 => Sha384::digest(input).into_iter().collect(),
        HashAlgorithm::Sha512 => Sha512::digest(input).into_iter().collect(),
        HashAlgorithm::Sha3_256 => Sha3_256::digest(input).into_iter().collect(),
        HashAlgorithm::Sha3_384 => Sha3_384::digest(input).into_iter().collect(),
        HashAlgorithm::Sha3_512 => Sha3_512::digest(input).into_iter().collect(),
    }
}
