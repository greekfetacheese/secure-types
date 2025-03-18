#[path = "../lib.rs"]
mod lib;

use std::io::Write;
use zeroize::Zeroize;

fn main() {
    let mut username = lib::SecureString::from("");
    let mut password = lib::SecureString::from("");

    username.string_mut(|user| {
        prompt("Username: ", user).unwrap();
    });

    password.string_mut(|pass| {
        prompt("Password: ", pass).unwrap();
    });

    let mut something_else = String::new();
    prompt(
        "Write something else to overwrite the previous allocation (password): ",
        &mut something_else,
    )
    .unwrap();

    drop(username);
    drop(password);
    something_else.zeroize();
    // Here despite that something_else is zeroized the memory allocation still has a copy of the data
    // There is no way to guarantee full erase of the data
    // Try running this test and comment the something_else prompt and search for the password in the memory dump
    // You will see that the password now it will be there
    // but the username is still gone because the password overtook the previous allocation (username) and so on...

    println!("Take a dump now");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn prompt(msg: &str, string: &mut String) -> Result<(), std::io::Error> {
    print!("{}", msg);
    std::io::stdout().flush().unwrap();

    std::io::stdin().read_line(string)?;
    Ok(())
}
