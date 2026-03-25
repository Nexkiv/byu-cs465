use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, OsRng},
    Aes256Gcm, KeyInit,
};
use rand::{thread_rng, RngCore};
use rsa::{
    pkcs1v15::{Pkcs1v15Encrypt, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    sha2::Sha256,
    signature::Verifier,
    RsaPublicKey,
};
use std::io::{self, Read, Write};
use std::net::TcpStream;

mod messages;
use messages::{EncryptedMessage, HelloMessage, ServerResponse};

fn main() {
    let mut stream = match TcpStream::connect("127.0.0.1:2222") {
        Ok(stream) => stream,
        Err(_e) => {
            println!("Could not connect to server. Check that it is running.");
            return ();
        }
    };
    println!("Connected to server");

    let pub_key = match send_hello_message(&mut stream) {
        Ok(pub_key) => pub_key,
        Err(_e) => {
            println!("Could not obtain public key.");
            return ();
        }
    };
    println!("Hello exchanged");

    match message_server_loop(&mut stream, pub_key) {
        Ok(()) => (),
        Err(_e) => {
            println!("Message stream closed early.");
            return ();
        }
    };
}

fn send_hello_message(stream: &mut TcpStream) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let mut nonce = [0u8; 32];
    thread_rng().fill_bytes(&mut nonce);

    // create an initial Hello Message
    let hello = HelloMessage {
        signed_message: vec![],
        pub_key: "".to_string(),
        nonce,
    };
    let json = hello.to_json()?;

    // write to the TCP stream
    stream.write_all(json.as_bytes())?;

    // read from the TCP stream
    // we assume that all messages are shorter than 4096 bytes and
    // will be read in one call to read()
    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer)?;
    // an example of how to convert the buffer to a JSON string
    // you can do something similar for other message types
    let server_hello_json =
        str::from_utf8(&buffer[..bytes_read]).expect("Server hello not in UTF8");

    let server_hello = HelloMessage::from_json(server_hello_json.to_string())?;

    // verify the signature
    let pub_key = RsaPublicKey::from_public_key_pem(&server_hello.pub_key)?;
    let verifying_key = VerifyingKey::<Sha256>::new(pub_key.clone());
    let signature = Signature::try_from(&server_hello.signed_message[..])?;
    verifying_key.verify(&nonce, &signature)?;

    Ok(pub_key)
}

fn message_server_loop(
    stream: &mut TcpStream,
    rsa_pub_key: RsaPublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // When I checked online this was the recommended wy of recieving user string input
        print!("Enter message: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input == "exit" {
            break;
        }

        let message = input;

        let key = Aes256Gcm::generate_key(OsRng);

        // encrypts the key so it can send it to the server
        let encrypted_key = rsa_pub_key.encrypt(&mut thread_rng(), Pkcs1v15Encrypt, &key)?;

        let cipher = Aes256Gcm::new(&key);

        let encrypted_message = match encrypt_message(message, encrypted_key, cipher.clone()) {
            Ok(encrypted_message) => encrypted_message,
            Err(_e) => {
                println!("Could not encrypt message.");
                return Err(Box::<dyn std::error::Error>::from(_e.to_string()));
            }
        };

        let json = encrypted_message.to_json()?;
        stream.write_all(json.as_bytes())?;

        let mut buffer = [0; 4096];
        let bytes_read = stream.read(&mut buffer)?;
        let response_json = String::from_utf8(buffer[..bytes_read].to_vec())?;

        let server_response = ServerResponse::from_json(response_json)?;
        let plaintext_bytes = match decrypt_message(server_response, cipher) {
            Ok(plaintext_bytes) => plaintext_bytes,
            Err(_e) => {
                println!("Could not encrypt message.");
                return Err(Box::<dyn std::error::Error>::from(_e.to_string()));
            }
        };

        let plaintext = String::from_utf8(plaintext_bytes)?;

        println!("Received: {}", plaintext);
    }

    Ok(())
}

fn encrypt_message(
    message: &str,
    encrypted_key: Vec<u8>,
    cipher: Aes256Gcm,
) -> Result<EncryptedMessage, aes_gcm::Error> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, message.as_ref())?;

    let encrypted_message = EncryptedMessage {
        encrypted_key,
        nonce_bytes: nonce.to_vec(),
        ciphertext,
    };

    Ok(encrypted_message)
}

fn decrypt_message(
    server_response: ServerResponse,
    cipher: Aes256Gcm,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let nonce_ga = vec_to_nonce(server_response.nonce_bytes).map_err(|_| aes_gcm::Error)?; // Convert String error to aes_gcm::Error

    let encrypted_message = server_response.encrypted_message;
    let plaintext_bytes = cipher.decrypt(&nonce_ga, encrypted_message.as_ref())?;

    Ok(plaintext_bytes)
}

// This was my workaround to convert the Vec[u8] nonce into something decrypt could use
fn vec_to_nonce(
    nonce_vec: Vec<u8>,
) -> Result<GenericArray<u8, aes_gcm::aead::consts::U12>, String> {
    // Convert Vec<u8> to [u8; 12]
    let nonce_array: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|v: Vec<u8>| format!("Expected 12-byte nonce, found {}", v.len()))?;

    // Convert array to owned GenericArray
    Ok(GenericArray::from(nonce_array))
}
