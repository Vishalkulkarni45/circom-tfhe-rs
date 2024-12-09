## Security and Operational Assumptions

TFHE-rs uses padding bits (extra bits on the most significant side) to prevent precision loss or overflow when operations exceed the range of encoded values. Padding is consumed during operations like addition to accommodate carries, ensuring accurate results. Without padding, further computations may produce incorrect outcomes. By default, TFHE-rs ensures 128-bit security with its cryptographic parameters, but advanced users can customize configurations using tools like the [Lattice Estimator](https://github.com/malb/lattice-estimator). For more details, refer to the [TFHE-rs security documentation](https://docs.zama.ai/tfhe-rs/get-started/security_and_cryptography).

Follow these guidelines to ensure correctness when using TFHE-rs:

- Avoiding Overflow: Be cautious of potential overflows during operations. TFHE-rs allows defining padding bits to accommodate carries and prevent overflow errors.
- Key Management: Keep the client key confidential and do not share it. The server key can be distributed to enable homomorphic computations on the server side.
- Data Types: Choose appropriate data types (FheUint or FheInt) and bit sizes based on the expected range of your data to optimize performance and security.

## Step-by-Step Guide with Example Using TFHE-rs

###  Set Up tfhe-rs Project

Set up a new Rust project and include TFHE-rs as a dependency in your `Cargo.toml`. Make sure you have Rust version 1.73 or higher installed. For more details refer [this](https://docs.zama.ai/tfhe-rs/guides/rust_configuration).

```toml
[dependencies]

[target.'cfg(target_arch = "x86_64")'.dependencies]
tfhe = { version = "0.8.7", features = [ "integer", "x86_64-unix" ] }

[target.'cfg(target_arch = "arm")'.dependencies]
tfhe = { version = "0.8.7", features = [ "integer", "aarch64-unix" ] }
```
### Import modules, configure, and generate keys.
Configure the parameters and generate the client and server keys:

```
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();
    let (client_key, server_key) = generate_keys(config);

    // Placeholder for subsequent steps

}
```

###  Set the Server Key and Encrypt Data
Set the server key to enable homomorphic computations and encrypt the data using the client key

```
// Server-side
set_server_key(server_key);

// Client-side
let clear_a = 27u8;
let clear_b = 128u8;
let a = FheUint8::encrypt(clear_a, &client_key)?;
let b = FheUint8::encrypt(clear_b, &client_key)?;

```
### Perform Homomorphic Computation and Decrypt the Result

Perform the addition operation on the encrypted data and decrypt the result using the client key

```
// Server-side
let result = a + b;

// Client-side
let decrypted_result: u8 = result.decrypt(&client_key)?;
let clear_result = clear_a + clear_b;
assert_eq!(decrypted_result, clear_result);
println!("Decrypted result: {}", decrypted_result);
Ok(())

```

This example demonstrated performing addition on encrypted data with TFHE-rs. Other supported operations follow a similar process. For more details refer this [documentation](https://docs.zama.ai/tfhe-rs/get-started/operations).


