use std::{
    fmt,
    fs::File,
    io::{self, Write},
    path::Path,
};

use env_logger::Env;
use halo2_proofs::{halo2curves::bn256::Fr, plonk::Circuit};
use num_bigint::BigUint;
use polyexen::{
    analyze::{bound_base, find_bounds_poly, Analysis},
    expr::ExprDisplay,
    plaf::{
        frontends::halo2::get_plaf, Cell, CellDisplay, Plaf, PlafDisplayBaseTOML,
        PlafDisplayFixedCSV,
    },
};

mod circuit;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let c = circuit::SummaMSTChip::init_empty();
    let k = 10;

    do_circuit_analysis(k, &c);
}

fn do_circuit_analysis(k: u32, c: &impl Circuit<Fr>) {
    let mut plaf = get_plaf(k, c).unwrap();
    plaf.simplify();
    write_files("mst_plaf", &plaf).unwrap();

    let p = BigUint::parse_bytes(b"100000000000000000000000000000000", 16).unwrap()
        - BigUint::from(159u64);
    let mut analysis = Analysis::new();

    let cell_fmt =
        |f: &mut fmt::Formatter<'_>, c: &Cell| write!(f, "{}", CellDisplay { c, plaf: &plaf });
    for offset in 0..plaf.info.num_rows {
        for poly in &plaf.polys {
            let mut exp = plaf.resolve(&poly.exp, offset);
            exp.simplify(&p);
            if exp.is_zero() {
                continue;
            }
            log::debug!(
                "\"{}\" {}",
                poly.name,
                ExprDisplay {
                    e: &exp,
                    var_fmt: cell_fmt
                }
            );
            // Fill bounds in analysis.vars_attrs
            find_bounds_poly(&exp, &p, &mut analysis);
        }
    }
    let bound_base = bound_base(&p);
    for (cell, attrs) in &analysis.vars_attrs {
        if attrs.bound == bound_base {
            continue;
        }
        log::debug!(
            "{} bound {:?}",
            CellDisplay {
                c: cell,
                plaf: &plaf
            },
            attrs.bound
        );
    }
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
