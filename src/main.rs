use std::{
    fs::File,
    io::{self, Write},
    path::Path,
};

use env_logger::Env;
use halo2_proofs::{halo2curves::bn256::Fr, plonk::Circuit};
use polyexen::plaf::{frontends::halo2::get_plaf, Plaf, PlafDisplayBaseTOML, PlafDisplayFixedCSV};

mod circuit;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let c = circuit::SummaMSTChip::init_empty();
    let k = 10;

    do_circuit_analysis(k, &c);
}

fn do_circuit_analysis(k: u32, c: &impl Circuit<Fr>) {
    let plaf = get_plaf(k, c).unwrap();
    write_files("mst", &plaf).unwrap();
}

fn write_files(name: &str, plaf: &Plaf) -> Result<(), io::Error> {
    if !Path::new("out").exists() {
        std::fs::create_dir("out")?;
        log::debug!("create out dir")
    }

    let mut base_file = File::create(format!("out/{}.toml", name))?;
    let mut fixed_file = File::create(format!("out/{}_fixed.csv", name))?;
    write!(base_file, "{}", PlafDisplayBaseTOML(plaf))?;
    write!(fixed_file, "{}", PlafDisplayFixedCSV(plaf))?;

    Ok(())
}
