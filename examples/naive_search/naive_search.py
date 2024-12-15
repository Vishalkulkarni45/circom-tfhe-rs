import random
import argparse

in1txt = "0.in1"
in2txt = "0.in2"
outtxt = "0.out"


parser = argparse.ArgumentParser(description="ops script")
parser.add_argument("plain_text_data_type", type=str, help="Plain text data type like u128,i64...")

args = parser.parse_args()
plain_text_data_type = args.plain_text_data_type

integer_type = plain_text_data_type[0]
integer_range = plain_text_data_type[1:]

cipher_text_data_type = ""

upper_range = 0
lower_range = 0

if integer_type == 'u':
    upper_range = 2 ** int(integer_range)
    cipher_text_data_type = f"FheUint{integer_range}"
else:
    lower_range = - 2 ** (int(integer_range) - 1)
    upper_range = 2 ** (int(integer_range) - 1) - 1
    cipher_text_data_type = f"FheInt{integer_range}"

N = 5
in2_val = random.randint(lower_range, upper_range)

inputs = {}
for i in range(N):
    in1str = in1txt + "["+ str(i) + "]"
    inputs[in1str] = random.randint(lower_range, upper_range)

inputs["0.in2"] = in2_val


import json

with open('input.json', 'w') as fp:
    json.dump(inputs, fp)

    open_bracket = '{'
    close_bracket = '}'

raw_code = f'''

use std::collections::HashMap;
use regex::Regex;
use serde_json::to_writer;
use tfhe::{cipher_text_data_type};
use std::fs::File;
use std::io::Read;

use tfhe::prelude::*;
use tfhe::{open_bracket}generate_keys, set_server_key, ConfigBuilder{close_bracket};
use serde_json::Value;

fn main()  -> Result<(), Box<dyn std::error::Error>> {open_bracket}
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
    let mut arrays: HashMap<String, Vec<{plain_text_data_type}>> = HashMap::new();
    let mut scalars: HashMap<String, {plain_text_data_type}> = HashMap::new();

    for (key, value) in data {open_bracket}
        // Check if the value can be converted to {plain_text_data_type}
      if let Some(int_value) = value.as_u64() {open_bracket}
            if array_re.is_match(&key) {open_bracket}
                if let Some(caps) = re.captures(&key) {open_bracket}
                    // If key is an array type, get the name and index
                    let name = &caps["base"];
                    let index= &caps["index"].parse::<usize>().unwrap();
                 
                    
                    // Insert into the corresponding vector in `arrays`
                    arrays.entry(name.to_string())
                          .or_insert_with(Vec::new)
                          .resize(N, 0);  // Ensure vector is long enough
                    arrays.get_mut(name).unwrap()[*index] = int_value as {plain_text_data_type};
                {close_bracket}
            {close_bracket}
            else {open_bracket}
                scalars.insert(key, int_value as {plain_text_data_type});
            {close_bracket}
        {close_bracket}
    {close_bracket}

    let mut cnt = {cipher_text_data_type}::encrypt(0 as {plain_text_data_type}, &client_key);
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(scalars["0.in2"], &client_key);
        let bool_val:{cipher_text_data_type} = val1.eq(&val2).cast_into();
        cnt = cnt + bool_val;
    {close_bracket}

    let mut outputs: HashMap<String, {plain_text_data_type}> = HashMap::new();
    let str: String = String::from("0.out");
    let y:{plain_text_data_type} = cnt.decrypt(&client_key);
    outputs.insert(str, y as {plain_text_data_type});

    let output_file = "output.json";

    let file = File::create(output_file)?;
    to_writer(&file, &outputs)?;

    Ok(())
{close_bracket}

'''

native_raw_code = f'''
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct InputStruct {open_bracket}
    pub in2: {plain_text_data_type},
    pub in1: Vec<{plain_text_data_type}>,
{close_bracket}

fn main() -> Result<(), Box<dyn std::error::Error>> {open_bracket}
    let mut file = File::open("input_struct.json")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let input_struct: InputStruct = serde_json::from_str(&contents)?;

    let mut cnt = 0;

    for num in input_struct.in1 {open_bracket}
        if num == input_struct.in2 {open_bracket}
            cnt += 1;
        {close_bracket}
    {close_bracket}
    let mut output_raw: HashMap<String, {plain_text_data_type}> = HashMap::new();

    output_raw.insert(String::from("0.out"), cnt);

    let file = File::create("output.json")?;
    serde_json::to_writer(file, &output_raw)?;

    Ok(())
{close_bracket}

'''

with open('native_code.rs', 'w') as fp:
    fp.write(native_raw_code)

with open('main.rs', 'w') as fp:
    fp.write(raw_code)