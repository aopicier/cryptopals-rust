use errors::*;
use serialize::from_hex;
use serialize::Serialize;

pub fn run() -> Result<(), Error> {
    let input_string = "49276d206b696c6c696e6720796f757220627261\
                        696e206c696b65206120706f69736f6e6f7573206\
                        d757368726f6f6d";

    compare_eq(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        &from_hex(input_string)?.to_base64(),
    )
}
