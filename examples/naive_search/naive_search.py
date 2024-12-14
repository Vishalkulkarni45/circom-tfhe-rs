import random
import argparse

in1txt = "0.in1"
in2txt = "0.in2"
outtxt = "0.out"


parser = argparse.ArgumentParser(description="ops script")
parser.add_argument("plain_text_data_type", type=str, help="Plain text data type like u128,i64...")

args = parser.parse_args()
plain_text_data_type = args.plain_text_data_type


N = 5
in2_val = random.randint(1, 10)

inputs = {}
for i in range(N):
    in1str = in1txt + "["+ str(i) + "]"
    inputs[in1str] = random.randint(1, 10)

inputs["0.in2"] = in2_val


import json

with open('input.json', 'w') as fp:
    json.dump(inputs, fp)

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
    const N:usize = 5;

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
    let mut arrays: HashMap<String, Vec<u128>> = HashMap::new();
    let mut scalars: HashMap<String, u128> = HashMap::new();

    for (key, value) in data {
        // Check if the value can be converted to u128
      if let Some(int_value) = value.as_str().and_then(|s| s.parse::<u128>().ok()) {
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

    let mut cnt = FheUint64::encrypt(0 as u128, &client_key);
    for i in 0..N {
        let val1 = FheUint64::encrypt(arrays["0.in1"][i], &client_key);
        let val2 = FheUint64::encrypt(scalars["0.in2"], &client_key);
        let bool_val:FheUint64 = val1.eq(&val2).cast_into();
        cnt = cnt + bool_val;
    }

    let mut outputs: HashMap<String, u128> = HashMap::new();
    let str: String = String::from("0.out");
    let y:u128 = cnt.decrypt(&client_key);
    outputs.insert(str, y as u128);

    let output_file = "output.json";

    let file = File::create(output_file)?;
    to_writer(&file, &outputs)?;

    Ok(())
}

'''

with open('main.rs', 'w') as fp:
    fp.write(raw_code)