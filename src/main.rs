use std::io::{BufWriter, Write};
use std::{fs, fs::File, path::{ Path, PathBuf } };

use anyhow::{ bail, Result };
use clap::{Args, Parser, ValueEnum};
use hex::{FromHex, ToHex};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{ json, Value, value::RawValue };
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

use rand::rngs::OsRng;
use ed25519_dalek::{ ExpandedSecretKey, Keypair, PublicKey as VerifyingKey, SecretKey, Signature as EdDSASignature, Verifier };

use GolemCertCli::*;

#[derive(Parser)]
enum GolemCertCli {
    Verify { signed_data_file: String },
    Sign(Sign),
    CreateKeyPair { key_pair_path: PathBuf },
}

#[derive(Args)]
struct Sign {
    json_file: PathBuf,
    signed_envelop_file: PathBuf,
    certificate_file: String,
    private_key_file: PathBuf,
    #[arg(long="hash")]
    hash_algorithm: Option<HashAlgorithm>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedEnvelop {
    signed_data: Box<RawValue>,
    signatures: Vec<Signature>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedEnvelopPrettify {
    signed_data: Value,
    signatures: Vec<Signature>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Signature {
    algorithm: SignatureAlgorithm,
    #[serde(serialize_with = "bytes_to_hex", deserialize_with = "hex_to_bytes")]
    signature_value: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<SignedEnvelop>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignatureAlgorithm {
    hash_algorithm: HashAlgorithm,
    encryption_algorithm: EncryptionAlgorithm,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum HashAlgorithm {
    Sha256, Sha384, Sha512, Sha3_256, Sha3_384, Sha3_512
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        HashAlgorithm::Sha512
    }
}

#[derive(Deserialize, Serialize)]
struct PublicKey {
    algorithm: EncryptionAlgorithm,
    #[serde(serialize_with = "bytes_to_hex", deserialize_with = "hex_to_bytes")]
    key: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<Value>,
}

#[derive(Deserialize, Serialize)]
struct PrivateKey {
    algorithm: EncryptionAlgorithm,
    #[serde(serialize_with = "bytes_to_hex", deserialize_with = "hex_to_bytes")]
    key: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ValueEnum)]
enum EncryptionAlgorithm {
    EdDSA
}

fn main() -> Result<()> {
    let command = GolemCertCli::parse();
    match &command {
        Verify { signed_data_file } => verify(signed_data_file),
        Sign(parameters) => sign(parameters),
        CreateKeyPair { key_pair_path } => create_key_pair(key_pair_path),
    }
}

fn read_certificate(certificate_path: &String, self_path: &PathBuf) -> Result<(Option<SignedEnvelop>, VerifyingKey)> {
    fn get_key_from_certificate_str(certificate: &str) -> Result<VerifyingKey> {
        let certificate: Value = serde_json::from_str(certificate)?;
        let public_key: PublicKey = serde_json::from_value(certificate["publicKey"].clone())?;
        VerifyingKey::from_bytes(&public_key.key).map_err(Into::into)
    }

    if certificate_path == "self" {
        let certificate_string = fs::read_to_string(self_path)?;
        let verifying_key = get_key_from_certificate_str(&certificate_string)?;
        Ok((None, verifying_key))
    } else {
        let certificate_string = fs::read_to_string(certificate_path)?;
        let envelop: SignedEnvelop = serde_json::from_str(&certificate_string)?;
        let verifying_key = get_key_from_certificate_str(envelop.signed_data.get())?;
        Ok((Some(envelop), verifying_key))
    }
}

fn sign(parameters: &Sign) -> Result<()> {
    let data = fs::read_to_string(&parameters.json_file)?;
    let parsed_json: Value = serde_json::from_str(&data)?;
    let prettify = SignedEnvelopPrettify { signed_data: parsed_json, signatures: vec![] };
    let pretty_string = serde_json::to_string_pretty(&prettify)?;
    let mut signed_envelop: SignedEnvelop = serde_json::from_str(&pretty_string)?;

    let hash_algorithm = parameters.hash_algorithm.clone().unwrap_or_default();
    if hash_algorithm != HashAlgorithm::Sha512 {
        bail!("Incompatible hash with signature");
    }
    let (signer, verifying_key) = read_certificate(&parameters.certificate_file, &parameters.json_file)?;
    let private_key_string = fs::read_to_string(&parameters.private_key_file)?;
    let private_key: PrivateKey = serde_json::from_str(&private_key_string)?;
    let secret_key = SecretKey::from_bytes(&private_key.key)?;
    let expanded_secret_key = ExpandedSecretKey::from(&secret_key);
    let signature_value = expanded_secret_key.sign(signed_envelop.signed_data.get().as_bytes(), &verifying_key);
    let signature = Signature {
        algorithm: SignatureAlgorithm { hash_algorithm: HashAlgorithm::Sha512, encryption_algorithm: EncryptionAlgorithm::EdDSA },
        signature_value: signature_value.to_bytes().into(),
        signer,
    };
    signed_envelop.signatures.push(signature);
    save_json_to_file(&parameters.signed_envelop_file, &signed_envelop)
}

fn verify(signed_data_file: &String) -> Result<()> {
    let signed_data_string = fs::read_to_string(signed_data_file)?;
    let signed_envelop: SignedEnvelop = serde_json::from_str(&signed_data_string)?;
    verify_signed_envelop(&signed_envelop)
}

fn verify_signed_envelop(signed_envelop: &SignedEnvelop) -> Result<()> {
    for signature in signed_envelop.signatures.iter() {
        let certificate_string = if let Some(envelop) = &signature.signer {
            verify_signed_envelop(envelop)?;
            &envelop.signed_data
        } else {
            &signed_envelop.signed_data
        };
        let certificate: Value = serde_json::from_str(certificate_string.get())?;
        let private_key: PrivateKey = serde_json::from_value(certificate["publicKey"].clone())?;
        let verifying_key = VerifyingKey::from_bytes(&private_key.key)?;
        let signature_value = EdDSASignature::from_bytes(&signature.signature_value)?;
        verifying_key.verify(signed_envelop.signed_data.get().as_bytes(), &signature_value)?;
    }
    Ok(())
}

fn _create_digest(input: &str, hash_type: &HashAlgorithm) -> Vec<u8> {
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

fn create_key_pair(key_pair_path: &PathBuf) -> Result<()> {
    let mut csprng = OsRng { };
    let keypair = Keypair::generate(&mut csprng);
    let public_key = PublicKey {
        algorithm: EncryptionAlgorithm::EdDSA,
        parameters: Some(json!({ "scheme": "Ed25519" })),
        key: keypair.public.to_bytes().into(),
    };
    let mut public_key_path = key_pair_path.clone();
    public_key_path.set_extension("pub");
    save_json_to_file(&public_key_path, &public_key)?;
    let private_key = PrivateKey {
        algorithm: EncryptionAlgorithm::EdDSA,
        parameters: Some(json!({ "scheme": "Ed25519" })),
        key: keypair.secret.to_bytes().into(),
    };
    let mut private_key_path = key_pair_path.clone();
    private_key_path.set_extension("key");
    save_json_to_file(&private_key_path, &private_key)
}

fn save_json_to_file<P: AsRef<Path>, C: ?Sized + Serialize>(path: &P, content: &C) -> Result<()> {
    let mut writer = BufWriter::new(File::create(path)?);
    serde_json::to_writer_pretty(&mut writer, content)?;
    writer.write(b"\n")?;
    writer.flush()?;
    Ok(())
}
