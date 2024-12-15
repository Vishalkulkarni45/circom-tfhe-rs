import random
import argparse

in1txt = "0.in1"
in2txt = "0.in2"
outtxt = "0.out"
# ops = ["add", "div", "eq", "gt", "geq", "lt", "leq", "mul", "neq", "sub", "xor", "pow", "idiv", "mod", "shl", "shr"];
ops = ["add", "div", "eq", "gt", "geq", "lt", "leq", "mul", "neq", "sub", "xor", "shl", "shr", "mod", "or", "and"]

N = 1

parser = argparse.ArgumentParser(description="ops script")
parser.add_argument("plain_text_data_type", type=str, help="Plain text data type like u8,i64...")

args = parser.parse_args()
plain_text_data_type = args.plain_text_data_type
cipher_text_data_type = ""

integer_type = plain_text_data_type[0]
integer_range = plain_text_data_type[1:]

upper_range = 0
lower_range = 0

if integer_type == 'u':
    upper_range = 2 ** int(integer_range)
    cipher_text_data_type = f"FheUint{integer_range}"
else:
    lower_range = - 2 ** (int(integer_range) - 1)
    upper_range = 2 ** (int(integer_range) - 1) - 1
    cipher_text_data_type = f"FheInt{integer_range}"


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
use tfhe::{open_bracket}generate_keys, set_server_key, ConfigBuilder, FheBool{close_bracket};
use serde_json::Value;



fn main()  -> Result<(), Box<dyn std::error::Error>> {open_bracket}
    const N:usize = 1;

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
        // Check if the value can be converted to u64
        if let Some(int_value) = value.as_u64() {open_bracket}
            if array_re.is_match(&key) {open_bracket}
                if let Some(caps) = re.captures(&key) {open_bracket}
                    // If key is an array type, get the name and index
                    let name = &caps["base"];
                    let index= &caps["index"].parse::<usize>().unwrap();
                    
                    // Insert into the corresponding vector in arrays
                    arrays.entry(name.to_string())
                          .or_insert_with(Vec::new)
                          .resize(N, 0);  // Ensure vector is long enough
                    arrays.get_mut(name).unwrap()[*index] = int_value as {plain_text_data_type} ;
                {close_bracket}
            {close_bracket}
            else {open_bracket}
                scalars.insert(key, int_value as {plain_text_data_type});
            {close_bracket}
        {close_bracket}
    {close_bracket}

    let mut out_add: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_add"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_add"][i], &client_key);
        out_add.push(val1 + val2);
    {close_bracket}

    let mut out_div: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_div"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_div"][i], &client_key);
        out_div.push(val1 / val2);
    {close_bracket}


let mut out_eq: Vec<FheBool> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_eq"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_eq"][i], &client_key);
        out_eq.push(val1.eq(val2));
    {close_bracket}

    let mut out_gt: Vec<FheBool> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_gt"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_gt"][i], &client_key);
        out_gt.push(val1.gt(val2));
    {close_bracket}

    let mut out_geq: Vec<FheBool> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_geq"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_geq"][i], &client_key);
        out_geq.push(val1.ge(val2));
    {close_bracket}

    let mut out_lt: Vec<FheBool> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_lt"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_lt"][i], &client_key);
        out_lt.push(val1.lt(val2));
    {close_bracket}

    let mut out_leq: Vec<FheBool> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_leq"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_leq"][i], &client_key);
        out_leq.push(val1.le(val2));
    {close_bracket}

    let mut out_sub: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_sub"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_sub"][i], &client_key);
        out_sub.push(val1 - val2);
    {close_bracket}

    let mut out_mul: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_mul"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_mul"][i], &client_key);
        out_mul.push(val1 * val2);
    {close_bracket}

    let mut out_shl: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_shl"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_shl"][i], &client_key);
        out_shl.push(val1 << val2);
    {close_bracket}

    let mut out_shr: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_shr"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_shr"][i], &client_key);
        out_shr.push(val1 >> val2);
    {close_bracket}

    let mut out_neq: Vec<FheBool> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_shr"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_shr"][i], &client_key);
        out_neq.push(val1.ne(val2));
    {close_bracket}

    let mut out_xor: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_xor"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_xor"][i], &client_key);
        out_xor.push(val1^val2);
    {close_bracket}

    let mut out_mod: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_mod"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_mod"][i], &client_key);
        out_mod.push(val1 % val2);
    {close_bracket}

    let mut out_or: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_or"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_or"][i], &client_key);
        out_or.push(val1 | val2);
    {close_bracket}

    let mut out_and: Vec<{cipher_text_data_type}> = vec![];
    for i in 0..N {open_bracket}
        let val1 = {cipher_text_data_type}::encrypt(arrays["0.in1_and"][i], &client_key);
        let val2 = {cipher_text_data_type}::encrypt(arrays["0.in2_and"][i], &client_key);
        out_and.push(val1 & val2);
    {close_bracket}
    
    let mut outputs: HashMap<String, {plain_text_data_type}> = HashMap::new();

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_add") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_add[i].decrypt(&client_key));
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_div") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_div[i].decrypt(&client_key));
    {close_bracket}


for i in 0..N {open_bracket}
        let str: String = String::from("0.out_eq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_eq[i].decrypt(&client_key) as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_gt") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_gt[i].decrypt(&client_key) as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_geq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_geq[i].decrypt(&client_key) as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_lt") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_lt[i].decrypt(&client_key) as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_leq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_leq[i].decrypt(&client_key) as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_sub") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_sub[i].decrypt(&client_key));
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_mul") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_mul[i].decrypt(&client_key));
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_shl") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_shl[i].decrypt(&client_key));
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_shr") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_shr[i].decrypt(&client_key));
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_neq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_neq[i].decrypt(&client_key) as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_xor") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_xor[i].decrypt(&client_key));
   {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_mod") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_mod[i].decrypt(&client_key));
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_or") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_or[i].decrypt(&client_key));
    {close_bracket}
    
    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_and") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_and[i].decrypt(&client_key));
    {close_bracket}

    let output_file = "output.json";

    let file = File::create(output_file)?;
    to_writer(&file, &outputs)?;

    Ok(())
{close_bracket}
'''
native_raw_code = f'''
use std::collections::HashMap;
use regex::Regex;
use serde_json::to_writer;
use std::fs::File;
use std::io::Read;

use serde_json::Value;



fn main()  -> Result<(), Box<dyn std::error::Error>> {open_bracket}
    const N:usize = 1;


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
        // Check if the value can be converted to u64
        if let Some(int_value) = value.as_u64() {open_bracket}
            if array_re.is_match(&key) {open_bracket}
                if let Some(caps) = re.captures(&key) {open_bracket}
                    // If key is an array type, get the name and index
                    let name = &caps["base"];
                    let index= &caps["index"].parse::<usize>().unwrap();
                    
                    // Insert into the corresponding vector in arrays
                    arrays.entry(name.to_string())
                          .or_insert_with(Vec::new)
                          .resize(N, 0);  // Ensure vector is long enough
                    arrays.get_mut(name).unwrap()[*index] = int_value as {plain_text_data_type} ;
                {close_bracket}
            {close_bracket}
            else {open_bracket}
                scalars.insert(key, int_value as {plain_text_data_type});
            {close_bracket}
        {close_bracket}
    {close_bracket}

    let mut out_add = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_add"][i];
        let val2 = arrays["0.in2_add"][i];
        out_add.push(val1 + val2);
    {close_bracket}

    let mut out_div = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_div"][i];
        let val2 = arrays["0.in2_div"][i];
        out_div.push(val1 / val2);
    {close_bracket}


let mut out_eq = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_eq"][i];
        let val2 = arrays["0.in2_eq"][i];
        out_eq.push(val1 == val2);
    {close_bracket}

    let mut out_gt = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_gt"][i];
        let val2 = arrays["0.in2_gt"][i];
        out_gt.push(val1 >val2);
    {close_bracket}

    let mut out_geq = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_geq"][i];
        let val2 = arrays["0.in2_geq"][i];
        out_geq.push(val1 >= val2);
    {close_bracket}

    let mut out_lt = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_lt"][i];
        let val2 = arrays["0.in2_lt"][i];
        out_lt.push(val1 < val2);
    {close_bracket}

    let mut out_leq = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_leq"][i];
        let val2 = arrays["0.in2_leq"][i];
        out_leq.push(val1 <= val2);
    {close_bracket}

    let mut out_sub = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_sub"][i];
        let val2 = arrays["0.in2_sub"][i];
        out_sub.push(val1 - val2);
    {close_bracket}

    let mut out_mul = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_mul"][i];
        let val2 = arrays["0.in2_mul"][i];
        out_mul.push(val1 * val2);
    {close_bracket}

    let mut out_shl = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_shl"][i];
        let val2 = arrays["0.in2_shl"][i];
        out_shl.push(val1 << val2);
    {close_bracket}

    let mut out_shr = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_shr"][i];
        let val2 = arrays["0.in2_shr"][i];
        out_shr.push(val1 >> val2);
    {close_bracket}

    let mut out_neq = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_shr"][i];
        let val2 = arrays["0.in2_shr"][i];
        out_neq.push(val1 != val2);
    {close_bracket}

    let mut out_xor = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_xor"][i];
        let val2 = arrays["0.in2_xor"][i];
        out_xor.push(val1^val2);
    {close_bracket}

    let mut out_mod = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_mod"][i];
        let val2 = arrays["0.in2_mod"][i];
        out_mod.push(val1 % val2);
    {close_bracket}

    let mut out_or = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_or"][i];
        let val2 = arrays["0.in2_or"][i];
        out_or.push(val1 | val2);
    {close_bracket}

    let mut out_and = vec![];
    for i in 0..N {open_bracket}
        let val1 = arrays["0.in1_and"][i];
        let val2 = arrays["0.in2_and"][i];
        out_and.push(val1 & val2);
    {close_bracket}
    
    let mut outputs: HashMap<String, {plain_text_data_type}> = HashMap::new();

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_add") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_add[i]);
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_div") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_div[i]);
    {close_bracket}


for i in 0..N {open_bracket}
        let str: String = String::from("0.out_eq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_eq[i] as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_gt") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_gt[i] as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_geq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_geq[i] as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_lt") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_lt[i] as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_leq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_leq[i] as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_sub") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_sub[i]);
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_mul") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_mul[i]);
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_shl") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_shl[i]);
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_shr") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_shr[i]);
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_neq") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_neq[i] as {plain_text_data_type});
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_xor") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_xor[i]);
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_mod") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_mod[i]);
    {close_bracket}

    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_or") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_or[i]);
    {close_bracket}
    
    for i in 0..N {open_bracket}
        let str: String = String::from("0.out_and") + "[" + &i.to_string() + "]";
        outputs.insert(str, out_and[i]);
    {close_bracket}

    let output_file = "output.json";

    let file = File::create(output_file)?;
    to_writer(&file, &outputs)?;

    Ok(())
{close_bracket}
'''
with open('native_code.rs', 'w') as fp:
    fp.write(native_raw_code)

with open('main.rs', 'w') as fp:
    fp.write(raw_code)