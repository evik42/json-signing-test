use std::io::{BufWriter, Write};
use std::{fs, fs::File, path::PathBuf};

use anyhow::Result;
use clap::{Args, Parser, ValueEnum};
use hex::{FromHex, ToHex};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
struct SignedEnvelop<'a> {
    #[serde(borrow)]
    signed_data: &'a RawValue,
    signatures: Vec<Signature>,
}

#[derive(Serialize)]
struct SignedEnvelopPrettify {
    signed_data: Value,
    signatures: Vec<Signature>,
}

#[derive(Deserialize, Serialize)]
struct Signature {
    algorithm: HashAlgorithm,
    #[serde(serialize_with = "bytes_to_hex", deserialize_with = "hex_to_bytes")]
    signature_value: Vec<u8>,
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

#[derive(Deserialize, Serialize)]
struct Certificate {

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
    let prettify = SignedEnvelopPrettify { signed_data: parsed_json, signatures: vec![] };
    let pretty_string = serde_json::to_string_pretty(&prettify)?;
    let mut signed_data: SignedEnvelop = serde_json::from_str(&pretty_string)?;

    let hash_algorithm = parameters.hash_algorithm.clone().unwrap_or_default();
    let hash = create_digest(signed_data.signed_data.get(), &hash_algorithm);
    let signature = Signature { algorithm: hash_algorithm, signature_value: hash };
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
    let signed_data: SignedEnvelop = serde_json::from_str(&signed_data_string)?;

    for (idx, signature) in signed_data.signatures.iter().enumerate() {
        let hash = create_digest(signed_data.signed_data.get(), &signature.algorithm);
        print!("Signature {} is ", idx);
        if signature.signature_value == hash {
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

pub fn bytes_to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
  where T: AsRef<[u8]>,
        S: Serializer
{
  serializer.serialize_str(&buffer.encode_hex::<String>())
}

pub fn hex_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
  where D: Deserializer<'de>
{
  use serde::de::Error;
  String::deserialize(deserializer)
    .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}
