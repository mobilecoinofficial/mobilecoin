//! Intel SGX SIGSTRUCT Dump Utility
//!
//! This utility will read a SIGSTRUCT (css) file from standard input or the
//! command-line, print it's contents (optionally as debug byte arrays) to
//! standard output or an output file.

use hex_fmt::HexFmt;
use mc_sgx_css::Signature;
use std::{
    convert::TryFrom,
    fmt::Write,
    fs,
    io::{self, Read, Write as IoWrite},
    mem,
    path::PathBuf,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Config {
    /// The SIGSTRUCT file to read, or stdin
    #[structopt(parse(from_os_str))]
    pub input: Option<PathBuf>,
    /// The output location, or stdout
    #[structopt(parse(from_os_str))]
    pub output: Option<PathBuf>,
}

fn main() {
    let config = Config::from_args();

    let input = if config.input.is_some() {
        std::fs::read(config.input.unwrap()).expect("Could not read input file")
    } else {
        // sigstruct structures should be 1208 bytes
        let mut bytes = vec![0u8; mem::size_of::<Signature>()];
        io::stdin()
            .read_exact(&mut bytes)
            .expect("Could not read SIGSTRUCT from standard input");
        bytes
    };

    let sigstruct = Signature::try_from(input.as_slice()).expect("Could not parse input");

    let mut output = String::with_capacity(8192);
    writeln!(output, "Signature {{").expect("Could not write output");
    writeln!(
        output,
        "    header: 0x{}, ",
        HexFmt(&sigstruct.header()[..])
    )
    .expect("Could not write output");
    writeln!(output, "    vendor: {:?}, ", sigstruct.vendor()).expect("Could not write output");
    writeln!(output, "    date: 0x{:02x?}, ", sigstruct.date()).expect("Could not write output");
    writeln!(
        output,
        "    header2: 0x{}, ",
        HexFmt(&sigstruct.header2()[..])
    )
    .expect("Could not write output");
    writeln!(
        output,
        "    swdefined: 0x{}, ",
        HexFmt(&sigstruct.swdefined()[..])
    )
    .expect("Could not write output");
    writeln!(
        output,
        "    MRSIGNER: 0x{}, ",
        HexFmt(&sigstruct.mrsigner()[..])
    )
    .expect("Could not write output");
    writeln!(
        output,
        "    signature: 0x{}, ",
        HexFmt(&sigstruct.signature()[..])
    )
    .expect("Could not write output");
    writeln!(output, "    miscselect: {}, ", sigstruct.misc_select())
        .expect("Could not write output");
    writeln!(output, "    miscmask: {}, ", sigstruct.misc_mask()).expect("Could not write output");
    writeln!(output, "    attributes: {}, ", sigstruct.attributes())
        .expect("Could not write output");
    writeln!(
        output,
        "    attributemask: {}, ",
        sigstruct.attribute_mask()
    )
    .expect("Could not write output");
    writeln!(
        output,
        "    MRENCLAVE: 0x{}, ",
        HexFmt(&sigstruct.mrenclave()[..])
    )
    .expect("Could not write output");
    writeln!(output, "    isvprodid: {}, ", sigstruct.product_id())
        .expect("Could not write output");
    writeln!(output, "    isvsvn: {}, ", sigstruct.version()).expect("Could not write output");
    writeln!(output, "    q1: 0x{}, ", HexFmt(&sigstruct.q1()[..]))
        .expect("Could not write output");
    writeln!(output, "    q2 0x{}, ", HexFmt(&sigstruct.q2()[..])).expect("Could not write output");
    writeln!(output, "}}").expect("Could not write output");

    if config.output.is_some() {
        fs::write(config.output.unwrap(), output.as_bytes()).expect("Could not write output file");
    } else {
        io::stdout()
            .write_all(output.as_bytes())
            .expect("Could not write output to standard out")
    }
}
