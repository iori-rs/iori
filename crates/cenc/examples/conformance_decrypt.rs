//! File adapter for the external conformance runner. Keys are public fixture keys.
use iori_cenc::{KeyMap, ParsedCenc};
use std::{env, fs, process};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 3 {
        return Err("usage: conformance_decrypt INPUT OUTPUT KID:KEY... [--init PATH]".into());
    }
    let mut keys = KeyMap::new();
    let mut init = None;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--init" {
            i += 1;
            init = Some(fs::read(args.get(i).ok_or("missing init path")?)?);
        } else {
            let (kid, key) = args[i].split_once(':').ok_or("expected KID:KEY")?;
            keys.insert(
                hex::decode(kid)?.try_into().map_err(|_| "KID length")?,
                hex::decode(key)?.try_into().map_err(|_| "key length")?,
            );
        }
        i += 1;
    }
    let mut data = fs::read(&args[0])?;
    let parsed = match init {
        Some(init) => ParsedCenc::parse_with_init(&data, &init)?,
        None => ParsedCenc::parse(&data)?,
    };
    if parsed.jobs.is_empty() {
        return Err("fixture contains no decrypt jobs".into());
    }
    println!("decrypt_jobs={}", parsed.jobs.len());
    parsed.decrypt_in_place(&mut data, &keys, 0)?;
    fs::write(&args[1], data)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}
