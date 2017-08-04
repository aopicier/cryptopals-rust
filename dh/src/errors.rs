use aes;

error_chain! {
    links {
       Aes(aes::Error, aes::ErrorKind); 
    }
}
