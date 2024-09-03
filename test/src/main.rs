use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use std::env;
// use std::fs::File;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::Path;
use tokio;

use kms::{Annotations, ProviderSettings};

const SOCK_ADDR: &str = "/tmp/luks.sock";

const PARAMS_FILE: &str = "./config/kms-params.json";

#[derive(Clone, Deserialize)]
struct Params {
    client_type: String,
    client_key_id: String,
    kms_instance_id: String,
    secret_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    if Path::new(SOCK_ADDR).exists() {
        std::fs::remove_file(SOCK_ADDR)?;
    }

    let listener = UnixListener::bind(SOCK_ADDR).expect("Failed to bind Unix socket");

    env::set_var("ALIYUN_IN_GUEST_KEY_PATH", "/home/daniel/disk-encrypt/luks-agent/test/config");

    let params_string = std::fs::read_to_string(PARAMS_FILE)?;
    let params = serde_json::from_str::<Params>(&params_string)?;

    let secret_name = params.secret_name;
    let provider_settings = json!({
        "client_type": params.client_type,
        "client_key_id": params.client_key_id,
        "kms_instance_id": params.kms_instance_id,
    });
    let provider_settings: ProviderSettings = provider_settings.as_object().unwrap().to_owned();

    // let client = kms::new_getter("aliyun", provider_settings.clone())
    //     .await?;

    // // to get resource using a get_resource_provider client we do not need the Annotations.
    // let key_u8 = client
    //     .get_secret(&secret_name, &Annotations::default())
    //     .await?;

    // let key_base64 = String::from_utf8(key_u8)?;
    // println!("key_base64: {:?}", key_base64);
    // let key = STANDARD.decode(&key_base64)?;
    // let mut file = File::create("../../../mykeyfile_test")?;
    // file.write_all(&key)?;

    // env::remove_var("ALIYUN_IN_GUEST_KEY_PATH");
    // Ok(())

    println!("luks-agent start listening...");
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let client = kms::new_getter("aliyun", provider_settings.clone())
                    .await?;

                // to get resource using a get_resource_provider client we do not need the Annotations.
                let key_u8 = client
                    .get_secret(&secret_name, &Annotations::default())
                    .await?;

                let key_base64 = String::from_utf8(key_u8)?;
                println!("{:?}", key_base64);
                let key = STANDARD.decode(&key_base64)?;
                stream.write(&key).unwrap();
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
    // env::remove_var("ALIYUN_IN_GUEST_KEY_PATH");
}