import random
import argparse

in1txt = "0.in1"
in2txt = "0.in2"
outtxt = "0.out"
# ops = ["add", "div", "eq", "gt", "geq", "lt", "leq", "mul", "neq", "sub", "xor", "pow", "idiv", "mod", "shl", "shr"];
ops = ["add", "div", "eq", "gt", "geq", "lt", "leq", "mul", "neq", "sub", "xor", "shl", "shr", "mod", "or", "and"]

N = 5

parser = argparse.ArgumentParser(description="ops script")
parser.add_argument("plain_text_data_type", type=str, help="Plain text data type like u8,i64...")

args = parser.parse_args()
plain_text_data_type = args.plain_text_data_type

integer_type = plain_text_data_type[0]
integer_range = plain_text_data_type[1:]

upper_range = 0
lower_range = 0

if integer_type == 'u':
    upper_range = 2 ** int(integer_range)
else:
    lower_range = - 2 ** (int(integer_range) - 1)
    upper_range = 2 ** (int(integer_range) - 1) - 1


inputs = {}
for i in range(N):
    for op in ops:
        in1ops = in1txt + "_" + op + "["+ str(i) + "]"
        in2ops = in2txt + "_" + op + "["+ str(i) + "]"
        outops = outtxt + "_" + op + "["+ str(i) + "]"

        inputs[in1ops] = random.randint(lower_range, upper_range)
        inputs[in2ops] = random.randint(lower_range, upper_range)

import json

with open('input.json', 'w') as fp:
    json.dump(inputs, fp)

raw_code = '''
use std::collections::HashMap;
use regex::Regex;
use serde_json::to_string;
use serde_json::to_writer;
use tfhe::FheUint16;
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
    let mut arrays: HashMap<String, Vec<u16>> = HashMap::new();
    let mut scalars: HashMap<String, u16> = HashMap::new();

    for (key, value) in data {
        // Check if the value can be converted to u64
        if let Some(int_value) = value.as_u64() {
            if array_re.is_match(&key) {
                if let Some(caps) = re.captures(&key) {
                    // If key is an array type, get the name and index
                    let name = &caps["base"];
                    let index= &caps["index"].parse::<usize>().unwrap();
                    // println!("{} {}", name, index);
                    
                    // Insert into the corresponding vector in arrays
                    arrays.entry(name.to_string())
                          .or_insert_with(Vec::new)
                          .resize(N, 0);  // Ensure vector is long enough
                    arrays.get_mut(name).unwrap()[*index] = int_value as u16;
                }
            }
            else {
                scalars.insert(key, int_value as u16);
            }
        }
    }

    let mut out_add: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_add"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_add"][i], &client_key);
        out_add.push(val1 + val2);
    }

    let mut out_div: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_div"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_div"][i], &client_key);
        out_div.push(val1 / val2);
    }

Changmin Cho, [08-11-2024 10:22]
let mut out_eq: Vec<FheBool> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_eq"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_eq"][i], &client_key);
        out_eq.push(val1.eq(val2));
    }

    let mut out_gt: Vec<FheBool> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_gt"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_gt"][i], &client_key);
        out_gt.push(val1.gt(val2));
    }

    let mut out_geq: Vec<FheBool> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_geq"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_geq"][i], &client_key);
        out_geq.push(val1.ge(val2));
    }

    let mut out_lt: Vec<FheBool> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_lt"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_lt"][i], &client_key);
        out_lt.push(val1.lt(val2));
    }

    let mut out_leq: Vec<FheBool> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_leq"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_leq"][i], &client_key);
        out_leq.push(val1.le(val2));
    }

    let mut out_sub: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_sub"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_sub"][i], &client_key);
        out_sub.push(val1 - val2);
    }

    let mut out_mul: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_mul"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_mul"][i], &client_key);
        out_mul.push(val1 * val2);
    }

    let mut out_shl: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_shl"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_shl"][i], &client_key);
        out_shl.push(val1 << val2);
    }

    let mut out_shr: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_shr"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_shr"][i], &client_key);
        out_shr.push(val1 >> val2);
    }

    let mut out_neq: Vec<FheBool> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_shr"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_shr"][i], &client_key);
        out_neq.push(val1.ne(val2));
    }

    let mut out_xor: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_xor"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_xor"][i], &client_key);
        out_xor.push(val1^val2);
    }

    let mut out_mod: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_mod"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_mod"][i], &client_key);
        out_mod.push(val1 % val2);
    }

    let mut out_or: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_or"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_or"][i], &client_key);
        out_or.push(val1 | val2);
    }

    let mut out_and: Vec<FheUint16> = vec![];
    for i in 0..N {
        let val1 = FheUint16::encrypt(arrays["0.in1_and"][i], &client_key);
        let val2 = FheUint16::encrypt(arrays["0.in2_and"][i], &client_key);
        out_and.push(val1 & val2);
    }
    
    let mut outputs: HashMap<String, u16> = HashMap::new();

    for i in 0..N {
        let str: String = String::from("0.out_add") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_add[i].decrypt(&client_key));
    }

    for i in 0..N {
        let str: String = String::from("0.out_div") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_div[i].decrypt(&client_key));
    }

Changmin Cho, [08-11-2024 10:22]
for i in 0..N {
        let str: String = String::from("0.out_eq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_eq[i].decrypt(&client_key) as u16);
    }

    for i in 0..N {
        let str: String = String::from("0.out_gt") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_gt[i].decrypt(&client_key) as u16);
    }

    for i in 0..N {
        let str: String = String::from("0.out_geq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_geq[i].decrypt(&client_key) as u16);
    }

    for i in 0..N {
        let str: String = String::from("0.out_lt") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_lt[i].decrypt(&client_key) as u16);
    }

    for i in 0..N {
        let str: String = String::from("0.out_leq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_leq[i].decrypt(&client_key) as u16);
    }

    for i in 0..N {
        let str: String = String::from("0.out_sub") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_sub[i].decrypt(&client_key));
    }

    for i in 0..N {
        let str: String = String::from("0.out_mul") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_mul[i].decrypt(&client_key));
    }

    for i in 0..N {
        let str: String = String::from("0.out_shl") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_shl[i].decrypt(&client_key));
    }

    for i in 0..N {
        let str: String = String::from("0.out_shr") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_shr[i].decrypt(&client_key));
    }

    for i in 0..N {
        let str: String = String::from("0.out_neq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_neq[i].decrypt(&client_key) as u16);
    }

    for i in 0..N {
        let str: String = String::from("0.out_xor") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_xor[i].decrypt(&client_key));
    }

    for i in 0..N {
        let str: String = String::from("0.out_mod") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_mod[i].decrypt(&client_key));
    }

    for i in 0..N {
        let str: String = String::from("0.out_or") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_or[i].decrypt(&client_key));
    }
    
    for i in 0..N {
        let str: String = String::from("0.out_and") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_and[i].decrypt(&client_key));
    }

    let output_file = "output.json";

    let file = File::create(output_file)?;
    to_writer(&file, &outputs)?;

    Ok(())
}
'''

with open('raw_circuit.rs', 'w') as fp:
    fp.write(raw_code)