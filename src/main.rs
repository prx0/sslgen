use clap::Parser;
use rcgen::{Certificate, RcgenError};
use std::{io::Write, str::FromStr};

#[derive(Debug)]
pub enum Encoding {
    PEM,
    DER,
}

// Useful to convert the input from
// the cli into a value of Encoding
impl FromStr for Encoding {
    type Err = String;

    fn from_str(encoding: &str) -> Result<Self, Self::Err> {
        match encoding.to_lowercase().as_str() {
            "pem" => Ok(Self::PEM),
            "der" => Ok(Self::DER),
            _ => unimplemented!("unavailable encoding"),
        }
    }
}

// We use clap to parse arguments from
// the cli easily using the derive approach
#[derive(Debug, Parser)]
pub struct Options {
    #[clap(long, help = "certificate to generate")]
    pub certificate: String,

    #[clap(long, help = "encoding to use for certificate and keys")]
    pub encoding: Encoding,

    // clap allows to design complex
    // structures to define the cli
    #[clap(flatten)]
    pub key_pair: KeyPairOptions,

    #[clap(long, help = "subject alt names for the certificate")]
    pub subject_alt_names: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct KeyPairOptions {
    #[clap(long, help = "private key to generate")]
    pub private_key: String,

    #[clap(long, help = "public key to generate")]
    pub public_key: String,
}

// Little helper to create a file and it's content
fn new_file(path: &str, data: &[u8]) -> Result<(), std::io::Error> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?
        .write_all(data)
}

// Stores the generated ssl credentials
pub struct Credentials {
    certificate: Vec<u8>,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl Credentials {
    // Generate ssl credentials with options provided by the cli
    pub fn from_options(options: &Options) -> Result<Self, RcgenError> {
        let certificate = rcgen::generate_simple_self_signed(&*options.subject_alt_names)?;
        Self::from_certificate(&certificate, &options.encoding)
    }

    pub fn from_certificate(
        certificate: &Certificate,
        encoding: &Encoding,
    ) -> Result<Self, RcgenError> {
        let (certificate, public_key, private_key) = match encoding {
            Encoding::DER => (
                certificate.serialize_der()?,
                certificate.get_key_pair().public_key_der(),
                certificate.get_key_pair().serialize_der(),
            ),
            Encoding::PEM => (
                certificate.serialize_pem()?.into_bytes(),
                certificate.get_key_pair().public_key_pem().into_bytes(),
                certificate.get_key_pair().serialize_pem().into_bytes(),
            ),
        };

        Ok(Self {
            certificate,
            public_key,
            private_key,
        })
    }

    // Pesists the crendentials into files
    pub fn save_into_files(
        credentials: &Credentials,
        options: &Options,
    ) -> Result<(), std::io::Error> {
        new_file(&options.certificate, &credentials.certificate)?;
        new_file(&options.key_pair.public_key, &credentials.public_key)?;
        new_file(&options.key_pair.private_key, &credentials.private_key)
    }
}

fn main() {
    let options = Options::parse();
    let credentials = Credentials::from_options(&options).expect("Unable to create credentials");

    Credentials::save_into_files(&credentials, &options)
        .expect("Unable to save credentials into file");
}
