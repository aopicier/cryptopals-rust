use crate::errors::*;
use serialize::from_hex;
use serialize::Serialize;
use xor::XOR;

pub fn run() -> Result<(), Error> {
    let input1 = "1c0111001f010100061a024b53535009181c";
    let input2 = "686974207468652062756c6c277320657965";
    compare_eq(
        "746865206b696420646f6e277420706c6179",
        &from_hex(input1)?.xor(&from_hex(input2)?).to_hex(),
    )
}
