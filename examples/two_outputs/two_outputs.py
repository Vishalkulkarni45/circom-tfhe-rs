import random

inputs = {};
inputs["0.a"] = random.randint(1, 10);
inputs["0.b"] = random.randint(1, 10);

import json

with open('input.json', 'w') as fp:
    json.dump(inputs, fp);

raw_code = '''
use std::collections::HashMap;
use regex::Regex;
use serde_json::to_string;
use serde_json::to_writer;
use tfhe::FheUint64;
use std::fs::File;
use std::io::Read;
use std::io::Write;

use tfhe::prelude::*;
use tfhe::FheUint;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
use serde_json::Value;


fn main()  -> Result<(), Box<dyn std::error::Error>> {

    let config = ConfigBuilder::default().build();

	// Key generation
	let (client_key, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let mut file = File::open("input.json")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse JSON into a HashMap
    let data: HashMap<String, Value> = serde_json::from_str(&contents)?;

    // Regular expression to capture keys like "in_add[0]"
    let re = Regex::new(r"^(?P<base>\d+\.[a-zA-Z0-9_]+)\[(?P<index>\d+)\]$").unwrap();
    let array_re = Regex::new(r"\[\d+\]").unwrap();
    
    // Separate parsed data into a nested HashMap or single values
    let mut arrays: HashMap<String, Vec<u64>> = HashMap::new();
    let mut scalars: HashMap<String, u64> = HashMap::new();

    for (key, value) in data {
        // Check if the value can be converted to i64
        if let Some(int_value) = value.as_u64() {
            if array_re.is_match(&key) {
                if let Some(caps) = re.captures(&key) {
                    // If key is an array type, get the name and index
                    let name = &caps["base"];
                    let index= &caps["index"].parse::<usize>().unwrap();
                    // println!("{} {}", name, index);
                    
                    // Insert into the corresponding vector in `arrays`
                    arrays.entry(name.to_string())
                          .or_insert_with(Vec::new)
                          .resize(N, 0);  // Ensure vector is long enough
                    arrays.get_mut(name).unwrap()[*index] = int_value;
                }
            }
            else {
                scalars.insert(key, int_value);
            }
        }
    }

    let mut outputs: HashMap<String, u64> = HashMap::new();

    let a = FheUint64::encrypt(scalars["a"], &client_key);
    let b = FheUint64::encrypt(scalars["b"], &client_key);
    let c = FheUint64::encrypt(3 as u64, &client_key);

    let a_add_b = a + b;
    let a_mul_c = a * c;

    let a_add_b_dec = a_add_b.decrypt(&client_key);
    let a_mul_c_dec = a_mul_c.decrypt(&client_key);

    outputs.insert(String::from("a_add_b"), a_add_b_dec);
    outputs.insert(String::from("a_mul_c"), a_mul_c_dec);

    let output_file = "output.json";

    let file = File::create(output_file)?;
    to_writer(&file, &outputs)?;

    Ok(())
}
'''

with open('raw_circuit.rs', 'w') as fp:
    fp.write(raw_code)