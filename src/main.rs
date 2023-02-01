use std::fs;
use std::ops::Deref;

use base64::{Engine as _, engine::general_purpose as base64encoder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use structopt::StructOpt;

use Command::*;

#[derive(Debug, StructOpt)]
enum Command {
    Verify { signed_data_file: String },
    Sign { json_file: String, signed_data_file: String },
}

#[derive(Deserialize, Serialize)]
struct SignedData<'a> {
    #[serde(borrow)]
    signed_data: &'a RawValue,
    signatures: Vec<Signature>,
}

#[derive(Deserialize, Serialize)]
struct Signature {
    algorithm: String,
    signature_value: String,
}

fn main() {
    let command = Command::from_args();
    match &command {
        Verify { signed_data_file } => verify(signed_data_file),
        Sign { json_file, signed_data_file } => sign(json_file, signed_data_file),
    }
}

fn sign(json_file: &String, signed_data_file: &String) {
    let data = fs::read_to_string(json_file).expect("Cannot read json data file");
    let _: Value = serde_json::from_str(&data).expect("File contents is not valid json");
    let raw_data = RawValue::from_string(data).expect("Cannot create raw json value from file contents");

    let hash = Sha256::digest(raw_data.get());
    let hash_string = base64encoder::STANDARD_NO_PAD.encode(&hash);
    let signature = Signature { algorithm: "sha256".to_string(), signature_value: hash_string };
    let signed_data = SignedData { signed_data: &raw_data, signatures: vec![signature] };
    fs::write(signed_data_file, serde_json::to_string_pretty(&signed_data).expect("Cannot serialize signed data json")).expect("Cannot write signed json file");
}

fn verify(signed_data_file: &String) {
    let signed_data_string = fs::read_to_string(signed_data_file).expect("Cannot read signed data file");
    let signed_data: SignedData = serde_json::from_str(&signed_data_string).expect("Signed data file does not comform to expected JSON schema");

    for (idx, signature) in signed_data.signatures.iter().enumerate() {
        if signature.algorithm != "sha256" {
            println!("Unsupported algorithm {}", &signature.algorithm);
        } else {
            let store_hash = base64encoder::STANDARD_NO_PAD.decode(&signature.signature_value).expect("Cannot decode BASE64 hash");
            let hash = Sha256::digest(signed_data.signed_data.get());
            print!("Signature {} is ", idx);
            if store_hash.as_slice() == hash.deref() {
                println!("valid");
            } else {
                println!("INVALID");
            }
        }
    }
}
