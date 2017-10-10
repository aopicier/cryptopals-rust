use aes;
use bignum;
use diffie_hellman;
use serialize;
use std;

error_chain! {
    links {
       Aes(aes::Error, aes::ErrorKind);
       BigNum(bignum::Error, bignum::ErrorKind);
       DH(diffie_hellman::errors::Error, diffie_hellman::errors::ErrorKind);
       Serialize(serialize::Error, serialize::ErrorKind);
    }

    foreign_links {
        Io(::std::io::Error) #[cfg(unix)];
        Utf8(::std::string::FromUtf8Error);
        BigNumOpenssl(::bignum::error::ErrorStack);
    }

    errors {
        ComparisonFailed(m: String) {
            description("comparison failed")
            display("{}", m)
        }

        ItemNotFound(m: String) {
            description("item not found")
            display("{}", m)
        }

        NotImplemented {
            description("challenge not implemented")
            display("not implemented")
        }

        NonAscii(u: Vec<u8>) {
            description("invalid input")
            display("invalid input: {:?}", u)
        }
    }
}

pub fn compare<T>(x: T, y: T) -> Result<()>
where
    T: Eq + std::fmt::Debug,
{
    if x == y {
        Ok(())
    } else {
        bail!(ErrorKind::ComparisonFailed(
            format!("Expected: {:?}, found: {:?}", x, y)
        ))
    }
}

pub fn run_exercise<F>(exercise: F, challenge_number: u8)
where
    F: Fn() -> Result<()>,
{
    match exercise() {
        Ok(_) => println!("Challenge {:02}: Success", challenge_number),
        Err(ref e) => match *e.kind() {
            ErrorKind::ComparisonFailed(_) => {
                println!("Challenge {:02}: Wrong result: {}", challenge_number, e)
            }
            ErrorKind::ItemNotFound(_) => println!(
                "Challenge {:02}: Expected item not found: {}",
                challenge_number,
                e
            ),
            ErrorKind::NotImplemented => println!("Challenge {:02}: {}", challenge_number, e),

            _ => {
                println!("Challenge {:02}: An error occured: {}", challenge_number, e);
                for e in e.iter().skip(1) {
                    println!("{: <4}caused by: {}", "", e);
                }
                if let Some(backtrace) = e.backtrace() {
                    println!("{: <4}: {:?}", "", backtrace);
                }
            }
        },
    };
}
