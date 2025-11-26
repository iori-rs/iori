use std::{
    collections::HashMap,
    ffi::OsString,
    fs::File,
    io::{Cursor, Read, Write},
    path::PathBuf,
    process::Command,
};

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use m3u8_rs::KeyMethod;

use crate::{
    SegmentFormat,
    error::{IoriError, IoriResult},
    util::http::HttpClient,
};

#[derive(Debug)]
pub enum IoriKey {
    Aes128 {
        key: [u8; 16],
        iv: [u8; 16],
    },
    ClearKey {
        keys: HashMap<String, String>,
    },
    SampleAes {
        key: [u8; 16],
        iv: [u8; 16],
        keys: HashMap<String, String>,
    },
}

impl IoriKey {
    pub fn clear_key(key: &str) -> IoriResult<Self> {
        let (kid, key) = key
            .split_once(':')
            .ok_or_else(|| IoriError::InvalidHexKey(key.to_string()))?;

        let mut keys = HashMap::new();
        keys.insert(kid.to_string(), key.to_string());
        Ok(Self::ClearKey { keys })
    }

    pub async fn from_key(
        client: &HttpClient,
        key: &m3u8_rs::Key,
        playlist_url: &reqwest::Url,
        media_sequence: u64,
        manual_key: Option<String>,
    ) -> IoriResult<Option<Self>> {
        Ok(match &key.method {
            KeyMethod::None => None,
            KeyMethod::AES128 => {
                let key_bytes = if let Some(key) = manual_key {
                    hex::decode(key)?
                } else {
                    client
                        .get(
                            playlist_url
                                .join(&key.uri.clone().expect("URI field in key must exist"))?,
                        )
                        .send()
                        .await?
                        .bytes()
                        .await?
                        .to_vec()
                };
                Some(Self::Aes128 {
                    key: key_bytes.try_into().map_err(IoriError::InvalidBinaryKey)?,
                    iv: key
                        .iv
                        .clone()
                        .and_then(|iv| {
                            let iv = iv.strip_prefix("0x").unwrap_or(&iv);
                            u128::from_str_radix(iv, 16).ok()
                        })
                        .unwrap_or(media_sequence as u128)
                        .to_be_bytes(),
                })
            }
            KeyMethod::SampleAES => {
                let Some(manual_key) = manual_key else {
                    return Err(IoriError::DecryptionKeyRequired);
                };

                // Support two formats:
                // 1. <kid>:<key>;<kid>:<key>;...
                // 2. <key>
                let mut keys = HashMap::new();
                for pair in manual_key.split(';') {
                    match pair.split_once(':') {
                        Some((kid, key)) if is_valid_kid_key_pair(kid, key) => {
                            keys.insert(kid.to_string(), key.to_string());
                        }
                        _ => tracing::warn!("Ignored key-only format: {}", pair),
                    }
                }

                let raw_key = if keys.is_empty() {
                    manual_key
                } else {
                    keys.iter().next().unwrap().1.clone()
                };
                let key_bytes =
                    hex::decode(raw_key).map_err(|_| IoriError::DecryptionKeyRequired)?;

                Some(Self::SampleAes {
                    key: key_bytes.try_into().map_err(IoriError::InvalidBinaryKey)?,
                    iv: key
                        .iv
                        .clone()
                        .and_then(|iv| {
                            let iv = iv.strip_prefix("0x").unwrap_or(&iv);
                            u128::from_str_radix(iv, 16).ok()
                        })
                        .unwrap_or(media_sequence as u128)
                        .to_be_bytes(),
                    keys,
                })
            }
            KeyMethod::Other(name) => match name.as_str() {
                "SAMPLE-AES-CENC" | "SAMPLE-AES-CTR" => {
                    tracing::debug!("{name} encryption detected. Using manual key.");

                    // <kid>:<key>;<kid>:<key>;...
                    let Some(manual_key) = manual_key else {
                        return Err(IoriError::DecryptionKeyRequired);
                    };
                    let mut keys = HashMap::new();
                    for pair in manual_key.split(';') {
                        match pair.split_once(':') {
                            Some((kid, key)) if is_valid_kid_key_pair(kid, key) => {
                                keys.insert(kid.to_string(), key.to_string());
                            }
                            _ => tracing::warn!("Ignored invalid key format: {}", pair),
                        }
                    }
                    if keys.is_empty() {
                        return Err(IoriError::InvalidHexKey(manual_key));
                    }

                    Some(Self::ClearKey { keys })
                }
                _ => unimplemented!("Unknown key method: {name}"),
            },
        })
    }

    pub fn to_decryptor(
        &self,
        segment_format: SegmentFormat,
        shaka_packager_command: Option<PathBuf>,
    ) -> IoriDecryptor {
        match self {
            IoriKey::Aes128 { key, iv } => IoriDecryptor::Aes128(Box::new(cbc::Decryptor::<
                aes::Aes128,
            >::new(
                key.into(), iv.into()
            ))),
            IoriKey::ClearKey { keys } => {
                if let Some(shaka_packager) = shaka_packager_command {
                    IoriDecryptor::ShakaPackager {
                        command: shaka_packager,
                        keys: keys.clone(),
                    }
                } else {
                    IoriDecryptor::Mp4Decrypt { keys: keys.clone() }
                }
            }
            IoriKey::SampleAes { key, iv, keys } => match segment_format {
                SegmentFormat::Mpeg2TS | SegmentFormat::Aac => {
                    IoriDecryptor::SampleAes { key: *key, iv: *iv }
                }
                _ => {
                    if let Some(shaka_packager) = shaka_packager_command {
                        IoriDecryptor::ShakaPackager {
                            command: shaka_packager,
                            keys: keys.clone(),
                        }
                    } else {
                        IoriDecryptor::Mp4Decrypt { keys: keys.clone() }
                    }
                }
            },
        }
    }
}

pub enum IoriDecryptor {
    Aes128(Box<cbc::Decryptor<aes::Aes128>>),
    Mp4Decrypt {
        keys: HashMap<String, String>,
    },
    ShakaPackager {
        command: PathBuf,
        keys: HashMap<String, String>,
    },
    SampleAes {
        key: [u8; 16],
        iv: [u8; 16],
    },
}

impl IoriDecryptor {
    pub async fn decrypt(self, data: &[u8]) -> IoriResult<Vec<u8>> {
        Ok(match self {
            IoriDecryptor::Aes128(decryptor) => decryptor.decrypt_padded_vec_mut::<Pkcs7>(data)?,
            IoriDecryptor::Mp4Decrypt { keys } => mp4decrypt::mp4decrypt(data, &keys, None)?,
            IoriDecryptor::ShakaPackager { command, keys } => {
                let temp_dir = tempfile::tempdir()?;
                let rand_suffix = rand::random::<u64>();
                let temp_input_file = temp_dir.path().join(format!("input_{rand_suffix}.mp4"));
                let temp_output_file = temp_dir.path().join(format!("output_{rand_suffix}.mp4"));

                {
                    let mut input = File::create(&temp_input_file)?;
                    input.write_all(data)?;
                    input.flush()?;
                }

                let mut command = Command::new(command);
                command
                    .arg("--quiet")
                    .arg("--enable_raw_key_decryption")
                    .arg({
                        let mut str = OsString::new();
                        str.push("input=");
                        str.push(temp_input_file.as_os_str());
                        str.push(",stream=0,output=");
                        str.push(temp_output_file.as_os_str());
                        str
                    });

                if !keys.is_empty() {
                    use std::fmt::Write;
                    let mut arg = String::new();
                    for (index, (kid, key)) in keys.iter().enumerate() {
                        if index != 0 {
                            arg.push(',');
                        }
                        write!(arg, "label={}:key_id={kid}:key={key}", index + 1).unwrap();
                    }

                    command.arg("--keys").arg(arg);
                }

                command.spawn()?.wait()?;

                let mut file = File::open(temp_output_file)?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                data
            }
            IoriDecryptor::SampleAes { key, iv } => {
                let mut reader = Cursor::new(data);
                let mut writer = Vec::new();
                iori_ssa::decrypt(&mut reader, &mut writer, key, iv).map(|_| writer)?
            }
        })
    }
}

fn is_valid_kid_key_pair(kid: &str, key: &str) -> bool {
    kid.len() == 32
        && key.len() == 32
        && kid.chars().all(|c| c.is_ascii_hexdigit())
        && key.chars().all(|c| c.is_ascii_hexdigit())
}
