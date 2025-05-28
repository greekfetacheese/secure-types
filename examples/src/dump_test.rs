use std::io::{Write, Read};
use zeroize::Zeroize;
use secure_types::SecureString;


// This code does not leave any copies of the string in memory
fn main() {
   let username = secure_prompt("Username: ").unwrap();
   let password = secure_prompt("Password: ").unwrap();

    drop(username);
    drop(password);

    println!("Take a dump now");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

// It's not perfect but does its job and doesn't leave any copies of the string in memory
// Try running this test and with the last 3 lines commented and see the password being in memory
fn secure_prompt(msg: &str) -> Result<SecureString, std::io::Error> {
    print!("{}", msg);
    std::io::stdout().flush()?;

    let mut buffer = [0u8; 1024];
    let bytes_read = std::io::stdin().read(&mut buffer)?;
    let secure = SecureString::from(String::from_utf8_lossy(&buffer[..bytes_read]).into_owned());
    buffer.zeroize();
    // make sure we overwrite the old string allocation
    print!("Press enter to continue");
    std::io::stdout().flush()?;
    let _ = std::io::stdin().read(&mut buffer)?;
    Ok(secure)
}