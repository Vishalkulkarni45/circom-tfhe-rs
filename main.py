import argparse
from dataclasses import dataclass
from enum import Enum
import json
import os
import subprocess
from pathlib import Path
import re
import time
import shutil
from collections import defaultdict

class AGateType(Enum):
    ADD = 'AAdd'
    DIV = 'ADiv'
    EQ = 'AEq'
    GT = 'AGt'
    GEQ = 'AGEq'
    LT = 'ALt'
    LEQ = 'ALEq'
    MUL = 'AMul'
    NEQ = 'ANeq'
    SUB = 'ASub'
    BW_XOR = 'AXor'
    MOD = 'AMod'
    BW_SHL = 'AShiftL'
    BW_SHR = 'AShiftR'
    BW_OR = 'ABitOr'
    BW_AND = 'ABitAnd'
    # ABitOr,
    # ABitAnd,


MAP_GATE_TYPE_TO_OPERATOR_STR = {
    AGateType.ADD: '+',
    AGateType.MUL: '*',
    AGateType.DIV: '/',
    AGateType.LT: 'lt',
    AGateType.SUB: '-',
    AGateType.EQ: 'eq',
    AGateType.NEQ: 'ne',
    AGateType.GT: 'gt',
    AGateType.GEQ: 'ge',
    AGateType.LEQ: 'le',
    AGateType.BW_XOR: "^",
    AGateType.MOD: "%",
    AGateType.BW_SHL: "<<",
    AGateType.BW_SHR: ">>",
    AGateType.BW_OR: "|",
    AGateType.BW_AND:"&"
}

def generate_tfhe_circuit(
    arith_circuit_path: Path,
    circuit_info_path: Path,
    tfhe_project_root: Path,
    plain_text_data_type: str,
    cipher_text_data_type: str,
    circuit_name:str
):

    # Create Client folder
    code = os.system(f"cd {tfhe_project_root} &&  mkdir client && cd client && touch client.rs")
    if code != 0:
        raise ValueError("Failed to create client folder")

    # Create Server folder
    code = os.system(f"cd {tfhe_project_root} &&  mkdir server && cd server && touch server.rs")
    if code != 0:
        raise ValueError("Failed to create server folder")


    open_bracket = '{'
    close_bracket = '}'
#Includes default code, such as setting keys, assigning inputs to the wire, etc.
    default_code = f"""
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::collections::HashMap;
use std::array::from_fn;
use {circuit_name}::client::{open_bracket}client_enc, decrypt_output{close_bracket};


use tfhe::prelude::*;
use tfhe::{cipher_text_data_type};

#[derive(Deserialize, Debug)]
struct Constants {open_bracket}
    value: String,
    wire_index: {plain_text_data_type},
{close_bracket}

#[derive(Debug, Deserialize)]
struct InputData {open_bracket}
    input_name_to_wire_index: HashMap<String, {plain_text_data_type}>,
    constants: HashMap<String, Constants>,
    output_name_to_wire_index: HashMap<String, {plain_text_data_type}>,
{close_bracket}

fn main()  -> Result<(), Box<dyn std::error::Error>> {open_bracket}

    let mut file = File::open("input_struct.json")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let input_struct: InputStruct = serde_json::from_str(&contents)?;
    let ele_to_idx = struct_members_to_index();

    let mut wires:[Option<{cipher_text_data_type}>; N ] = from_fn(|_| None);

    //Client encrypts the inputs and provides the encrypted data, along with the server and client keys.
    let (enc_input, client_key, server_keys) = client_enc(input_struct, &mut wires)?;


    let mut file = File::open("circuit_info.json")?;
    let mut raw_data = String::new();
    file.read_to_string(&mut raw_data)?;

    // Deserialize the JSON data
    let data: InputData = serde_json::from_str(&raw_data).unwrap();

    // Server take the encrypted input and server key to perform the operations on the encrypted data
       server_compute(
        enc_input,
        server_keys,
        data.input_name_to_wire_index,
        ele_to_idx,
        &mut wires,
    );

"""

    total_wires = 0

    with open(circuit_info_path, 'r') as f:
        raw = json.load(f)

    input_name_to_wire_index = {k: int(v) for k, v in raw['input_name_to_wire_index'].items()}

    input_struct_ele = {}
    struct_to_nes_vec = []
    struct_ele_to_idx = []


    nth_struct_ele = 0
    # Generates the Input struct along with its helper function struct_to_vec
    # struct_to_vec converts struct to nested vector
    for k, v in input_name_to_wire_index.items():
        if ']' in k:
            after_dot = k.split('.')[1]
            result = after_dot.split('[')[0]

            if f'{result}:Vec<{plain_text_data_type}>,' not in input_struct_ele:
                input_struct_ele[f'{result}:Vec<{plain_text_data_type}>,'] = 0
                struct_to_nes_vec.append(f'input.{result}.clone(),')
                struct_ele_to_idx.append(f'data_members_index.insert(String::from("{result}"),{nth_struct_ele});')
                nth_struct_ele+=1
        else:
            input_struct_ele[f'{k[2:]}:{plain_text_data_type},'] = 0
            struct_to_nes_vec.append(f'[input.{k[2:]}.clone()].to_vec(),')
            struct_ele_to_idx.append(f'data_members_index.insert(String::from("{k[2:]}"),{nth_struct_ele});')
            nth_struct_ele+=1


    # To remove the last comma
    tmp = struct_to_nes_vec.pop()
    tmp = tmp[:-1]
    struct_to_nes_vec.append(tmp)
    constants: dict[str, dict[str, int]] = raw['constants']


    # Each gate line looks like this: '2 1 1 0 3 AAdd'
    @dataclass(frozen=True)
    class Gate:
        num_inputs: int
        num_outputs: int
        gate_type: AGateType
        inputs_wires: list[int]
        output_wire: int
    with open(arith_circuit_path, 'r') as f:
        first_line = next(f)
        num_gates, num_wires = map(int, first_line.split())
        total_wires = num_wires
        second_line = next(f)
        num_inputs = int(second_line.split()[0])
        third_line = next(f)
        num_outputs = int(third_line.split()[0])
        # Skip the next line
        next(f)


        # Read the gate lines
        gates: list[Gate] = []
        for line in f:
            line = line.split()
            num_inputs = int(line[0])
            num_outputs = int(line[1])
            inputs_wires = [int(x) for x in line[2:2+num_inputs]]
            # Support 2 inputs only for now
            assert num_inputs == 2 and num_inputs == len(inputs_wires)
            output_wires = list(map(int, line[2+num_inputs:2+num_inputs+num_outputs]))
            output_wire = output_wires[0]
            # Support 1 output only for now
            assert num_outputs == 1 and num_outputs == len(output_wires)
            gate_type = AGateType(line[2+num_inputs+num_outputs])
            gates.append(Gate(num_inputs, num_outputs, gate_type, inputs_wires, output_wire))
    assert len(gates) == num_gates
    # Make inputs to circuit (not wires!!) from the user config
    # Initialize a list inputs with num_wires with value=None
    inputs_str_list = []
    # Fill in the constants
    for _, o in constants.items():
        value = int(o['value'])
        # descaled_value = value / (10 ** scale)
        wire_index = int(o['wire_index'])
        # Should check if we should use cfix instead
        inputs_str_list.append(f"wires[{wire_index}] =  Some({cipher_text_data_type}::try_encrypt({value} as {plain_text_data_type}, &client_key)?);")

    # Translate bristol gates to tfhe operations
    # E.g.
    # '2 1 1 0 2 AAdd' in bristol
    #   is translated to
    # 'wires[2] = wires[1] + wires[0]' in tfhe
    gates_str_list = []
    for gate in gates:
        gate_str = ''
        if gate.gate_type not in MAP_GATE_TYPE_TO_OPERATOR_STR:
            raise ValueError(f"Gate type {gate.gate_type} is not supported")
        else:
            operator_str = MAP_GATE_TYPE_TO_OPERATOR_STR[gate.gate_type]
            if operator_str in ('le', 'lt', 'gt', 'ge', 'eq','ne'):
                gate_str = f'wires[{gate.output_wire}] = Some(wires[{gate.inputs_wires[0]}].as_ref().unwrap().{operator_str}(wires[{gate.inputs_wires[1]}].as_ref().unwrap()).cast_into());'
            else:
                gate_str = f'wires[{gate.output_wire}] = Some(wires[{gate.inputs_wires[0]}].as_ref().unwrap() {operator_str} wires[{gate.inputs_wires[1]}].as_ref().unwrap());'
        gates_str_list.append(gate_str)

    gates_str = '\n'.join(gates_str_list)
    input_struct = '\n'.join(input_struct_ele)
    struct_to_nes_vec = '\n'.join(struct_to_nes_vec)
    ele_to_idx = '\n'.join(struct_ele_to_idx)
    inputs_str_list = '\n'.join(inputs_str_list)

    open_bracket = '{'
    close_bracket = '}'

#Combines all the functions to create tfhe-rs file
    circuit_code = f"""
const N:usize = {total_wires};\n

use {circuit_name}::server::server_compute;

use {circuit_name}::{open_bracket}struct_members_to_index, InputStruct{close_bracket};


    {default_code}

 //Decrypt the output wire and save it to output.json
 decrypt_output(data.output_name_to_wire_index, &wires, client_key)?;

 Ok(())
{close_bracket}
"""
    client_code = f"""

use std::{open_bracket}collections::HashMap, fs::File{close_bracket};

use tfhe::{open_bracket}
    generate_keys,
    prelude::{open_bracket}FheDecrypt, FheTryEncrypt{close_bracket},
    ClientKey, ConfigBuilder, {cipher_text_data_type}, ServerKey,
{close_bracket};

use crate::{open_bracket}struct_to_vec, InputStruct{close_bracket};


pub fn client_enc<const N:usize>(
    raw_input: InputStruct,
    wires: &mut [Option<{cipher_text_data_type}>; N]
) -> Result<(Vec<Vec<{cipher_text_data_type}>>, ClientKey, ServerKey), Box<dyn std::error::Error>> {open_bracket}
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);

    let inputs = struct_to_vec(raw_input);

    let enc_input: Vec<Vec<{cipher_text_data_type}>> = inputs
        .into_iter()
        .map(|input|{open_bracket}
            input
                .into_iter()
                .map(|ith_input| {cipher_text_data_type}::try_encrypt(ith_input, &client_key))
                .collect::<Result<Vec<_>, _>>()
        {close_bracket})
        .collect::<Result<Vec<_>, _>>()?;

    {inputs_str_list}

    Ok((enc_input, client_key, server_keys))
{close_bracket}


pub fn decrypt_output<const N: usize>(
    output_name_to_wire_index: HashMap<String,{plain_text_data_type}>,
    wires: &[Option<{cipher_text_data_type}>; N],
    client_key: ClientKey,
) -> Result<(), Box<dyn std::error::Error>> {open_bracket}
    let mut output_raw: HashMap<String, {plain_text_data_type}> = HashMap::new();
    for (name, index) in output_name_to_wire_index.into_iter() {open_bracket}
        let index_usize = index as usize;
        let decrypted_result: {plain_text_data_type} = wires[index_usize].as_ref().unwrap().decrypt(&client_key);
        output_raw.insert(name, decrypted_result);
    {close_bracket}
    let file = File::create("output.json")?;
    serde_json::to_writer(file, &output_raw)?;

    Ok(())
{close_bracket}

"""


    lib_code = f"""
    use std::collections::HashMap;
    use serde::Deserialize;

    #[path = "../client/client.rs"]
    pub mod client;

    #[path = "../server/server.rs"]
    pub mod server;

    #[derive(Debug, Deserialize)]
    pub struct InputStruct {open_bracket}
        {input_struct}
    {close_bracket}

    pub fn struct_members_to_index()  ->  HashMap<String,usize> {open_bracket}
    let mut data_members_index = HashMap::new();

    {ele_to_idx}
    data_members_index

    {close_bracket}

    pub fn struct_to_vec(input:InputStruct) -> Vec<Vec<{plain_text_data_type}>> {open_bracket}

        vec![{struct_to_nes_vec}]

    {close_bracket}


    """

    server_code = f"""
use std::collections::HashMap;

use tfhe::{open_bracket}prelude::{open_bracket}CastInto, FheEq,FheOrd{close_bracket}, set_server_key, {cipher_text_data_type}, ServerKey{close_bracket};

pub fn server_compute<const N: usize>(
    enc_input: Vec<Vec<{cipher_text_data_type}>>,
    server_keys: ServerKey,
    input_name_to_wire_index: HashMap<String, {plain_text_data_type}>,
    ele_to_idx: HashMap<String, usize>,
    wires: &mut [Option<{cipher_text_data_type}>; N],
) {open_bracket}
    // Populate wires based on input_name_to_wire_index
    for (name, index) in input_name_to_wire_index.into_iter() {open_bracket}
        // parse string: name
        if name.contains("[") {open_bracket}
            let start_index = name.find('[').unwrap() + 1;
            let end_index = name.find(']').unwrap();

            let number_in_brackets = &name[start_index..end_index];
            let number_usize = number_in_brackets.parse::<usize>().unwrap();
            let index_usize = index as usize;
            assert!(
                wires[index_usize].is_none(),
                "Wire[{open_bracket}{close_bracket}] is already filled",
                index_usize
            );
            let data_member = &name[2..start_index - 1];
            let idx = ele_to_idx.get(data_member).unwrap();
            wires[index_usize] = Some(enc_input[*idx][number_usize].clone());
        {close_bracket} else {open_bracket}
            let data_member = &name[2..];
            let idx = ele_to_idx.get(data_member).unwrap();
            assert!(enc_input[*idx].len() == 1);
            let index_usize = index as usize;
            assert!(
                wires[index_usize].is_none(),
                "Wire[{open_bracket}{close_bracket}] is already filled",
                index_usize
            );
            wires[index_usize] = Some(enc_input[*idx][0].clone());
        {close_bracket}
    {close_bracket}
    set_server_key(server_keys);

    {gates_str}

{close_bracket}

    """
    code = os.system(f"cd {tfhe_project_root}/src && touch lib.rs")
    if code != 0:
        raise ValueError("Failed to create lib.rs")


    tfhe_lib_path = tfhe_project_root / 'src' / 'lib.rs'
    with open(tfhe_lib_path, 'w') as f:
        f.write(lib_code)

    tfhe_client_path = tfhe_project_root / 'client' / 'client.rs'
    with open(tfhe_client_path, 'w') as f:
        f.write(client_code)

    tfhe_server_path = tfhe_project_root / 'server' / 'server.rs'
    with open(tfhe_server_path, 'w') as f:
        f.write(server_code)

    out_tfhe_path = tfhe_project_root / 'src' / 'main.rs'
    with open(out_tfhe_path, 'w') as f:
        f.write(circuit_code)

def run_tfhe_circuit(
    tfhe_project_root: Path,
) -> str:
    # Compile and run tfhe in the local machine
    command = f'cd {tfhe_project_root} && cargo build --release  && cargo run --release'

    try:
        # Capture and print the output/error for debugging
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("Build output:", result.stdout)
        print("Build errors:", result.stderr)
    except subprocess.CalledProcessError as e:
        print("Build failed!")
        print("stdout:", e.stdout)
        print("stderr:", e.stderr)
        raise ValueError(f"Failed to run TFHE: {e=}")

    output_dir = tfhe_project_root / 'output.json'
    with open(output_dir, 'r') as file:
    # Load the contents of the file into a Python dictionary
        data = json.load(file)

    return data


def main():
    parser = argparse.ArgumentParser(description="Compile circom to JSON and Bristol and circuit info files.")
    parser.add_argument("circuit_name", type=str, help="The name of the circuit (used for input/output file naming)")
    parser.add_argument("plain_text_data_type", type=str, help="Plain text data type like u8, u16, u64 ..  or i8, i16 ..")

    args = parser.parse_args()
    circuit_name = args.circuit_name
    plain_text_data_type = args.plain_text_data_type
    cipher_text_data_type = ""

    if plain_text_data_type[0] == 'u':
        cipher_text_data_type = f"FheUint{plain_text_data_type[1:]}"

    elif plain_text_data_type[0] == 'i':
        cipher_text_data_type = f"FheInt{plain_text_data_type[1:]}"

    else:
        print("Incorrect data type; it should be u8, u16, u64 ..  or i8, i16 ..")
        quit()

    # defining directory
    PROJECT_ROOT = Path(__file__).parent
    CIRCOM_2_ARITHC_PROJECT_ROOT = PROJECT_ROOT / '..' / 'circom-2-arithc'
    TFHE_PROJECT_ROOT = PROJECT_ROOT / 'outputs' / f'{circuit_name}'
    TFHE_CIRCUIT_DIR = TFHE_PROJECT_ROOT / 'src'
    TFHE_RAW_PROJECT_ROOT = PROJECT_ROOT / 'outputs' / f'{circuit_name}_raw'
    TFHE_RAW_CIRCUIT_DIR = TFHE_RAW_PROJECT_ROOT / 'src'
    EXAMPLES_DIR = PROJECT_ROOT / 'examples'
    circuit_dir = EXAMPLES_DIR / circuit_name
    circom_path = circuit_dir / 'circuit.circom'


    # Create outputs folder

    code = os.system(f"cd {PROJECT_ROOT} && mkdir -p outputs")
    if code != 0:
        raise ValueError("Failed to outputs folder")

    # Step 0: generate Rust directory in the TFHE-RS repo; 2 repositories
    directory_path = TFHE_PROJECT_ROOT

    # Check if the directory exists
    if os.path.exists(directory_path) and os.path.isdir(directory_path):
    # Delete the directory and its contents
        shutil.rmtree(directory_path)
        print(f"Directory '{directory_path}' has been deleted.")

    directory_path_raw = TFHE_RAW_PROJECT_ROOT
    if os.path.exists(directory_path_raw) and os.path.isdir(directory_path_raw):
    # Delete the directory and its contents
        shutil.rmtree(directory_path_raw)
        print(f"Directory '{directory_path_raw}' has been deleted.")

    project_name = circuit_name
    try:
        subprocess.run(["cargo", "new", project_name], check=True, cwd=PROJECT_ROOT / 'outputs')
        print(f"Rust project '{project_name}' created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        raise RuntimeError(f"Failed to create the Rust project '{project_name}'.") from None

    new_dependency = """
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"  # Optional, for JSON support
regex = "1"


[target.'cfg(target_arch = "x86_64")'.dependencies]
tfhe = { version = "0.8.7", features = [ "integer", "x86_64-unix" ] }

[target.'cfg(target_arch = "arm")'.dependencies]
tfhe = { version = "0.8.7", features = [ "integer", "aarch64-unix" ] }

\n
    """
    with open(TFHE_PROJECT_ROOT / 'Cargo.toml', 'a') as file:
        file.write(new_dependency)

    project_name_raw = f'{circuit_name}_raw'
    try:
        subprocess.run(["cargo", "new", project_name_raw], check=True, cwd=PROJECT_ROOT / 'outputs')
        print(f"Rust project '{project_name_raw}' created successfully.")
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to create the Rust project '{project_name_raw}'.") from None

    new_dependency = """
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"  # Optional, for JSON support
regex = "1"

[target.'cfg(target_arch = "x86_64")'.dependencies]
tfhe = { version = "0.8.7", features = [ "boolean", "shortint", "integer", "x86_64-unix" ] }

[target.'cfg(target_arch = "arm")'.dependencies]
tfhe = { version = "0.8.7", features = [ "boolean", "shortint", "integer", "aarch64-unix" ] }
    """
    with open(TFHE_RAW_PROJECT_ROOT / 'Cargo.toml', 'a') as file:
        file.write(new_dependency)

    # Step 1a: run circom-2-arithc
    code = os.system(f"cd {CIRCOM_2_ARITHC_PROJECT_ROOT} && ./target/release/circom-2-arithc --input {circom_path} --output {TFHE_PROJECT_ROOT}")
    if code != 0:
        raise ValueError(f"Failed to compile circom. Error code: {code}")

    # Step 1b: run circuit script
    # python {circuit}.py
    code = os.system(f"cd {circuit_dir} && python3 {circuit_name}.py {plain_text_data_type}")
    if code != 0:
        raise ValueError(f"Failed to run {circuit_name}.py. Error code: {code}")

    # step 1c: make a modified input
    # Assume data is a dictionary parsed from JSON
    with open(circuit_dir / 'input.json', 'r') as f:
        data = json.load(f)

    key_regex = re.compile(r"^(?P<base>\d+\.[a-zA-Z0-9_]+)\[(?P<index>\d+)\]$")
    array_regex = re.compile(r"\[\d+\]")


    # Separate parsed data into a nested dictionary for arrays and single values for scalars
    arrays = defaultdict(lambda: [])
    scalars = {}

    for key, value in data.items():
        # Check if value can be treated as an integer
        if isinstance(value, int):
            if array_regex.search(key):
                match = key_regex.match(key)
                if match:
                    # If key is an array type, get the name and index
                    name = match.group("base")
                    index = int(match.group("index"))
                    name = name.split('.')[1]

                    # Ensure the vector is long enough
                    while len(arrays[name]) <= index:
                        arrays[name].append(0)

                    # Assign the integer value to the correct index
                    arrays[name][index] = int(value)
            else:
                # If key is not an array, store it as a scalar
                key = key.split('.')[1]
                scalars[key] = int(value)


    # Converts the input.json to input_struct.json which can be serialised to input_struct by the rust
    json_string = "{\n"
    for key, value in arrays.items():
        # Check if the value is a list
        if isinstance(value, list):
            value_str = "[" + ", ".join(f'{item}' for item in value) + "]"
        else:
            value_str = f'{value}'
        json_string += f'    "{key}": {value_str},\n'

    for key, value in scalars.items():
        # Check if the value is a list
        if isinstance(value, list):
            value_str =  ", ".join(f'{item}' for item in value)
        else:
            value_str = f'{value}'
        json_string += f'    "{key}": {value_str},\n'
    # Remove the last comma and add closing bracket
    json_string = json_string.rstrip(",\n") + "\n}"

    # Write the JSON string to a file
    with open(circuit_dir / 'input_struct.json', "w") as json_file:
        json_file.write(json_string)

    # Step 1d: copy raw circuit into output folder
    os.chdir(circuit_dir)
    os.rename('raw_circuit.rs', 'main.rs')

    source_file = circuit_dir / 'main.rs'
    destination_file = TFHE_RAW_CIRCUIT_DIR / 'main.rs'
    shutil.copy(source_file, destination_file)

    # Step 1d: copy input.json into raw_circuit directory and circuit directory
    code = os.system(f"cd {circuit_dir} && cp ./input.json {TFHE_RAW_PROJECT_ROOT} && cp ./input_struct.json {TFHE_RAW_PROJECT_ROOT}")
    if code != 0:
        raise ValueError(f"Failed to copy input.json to RAW_CIRCUIT_DIR. Error code: {code}")
    code = os.system(f"cd {circuit_dir} && cp ./input.json {TFHE_PROJECT_ROOT} && cp ./input_struct.json {TFHE_PROJECT_ROOT}")
    if code != 0:
        raise ValueError(f"Failed to copy input.json to CIRCUIT_DIR. Error code: {code}")

    # Step 2: run arithc-to-bristol (NO NEEDED)

    bristol_path = TFHE_PROJECT_ROOT / "circuit.txt"
    circuit_info_path = TFHE_PROJECT_ROOT / "circuit_info.json"

    # Step 3: generate TFHE circuit
    generate_tfhe_circuit(
        bristol_path,
        circuit_info_path,
        TFHE_PROJECT_ROOT,
        plain_text_data_type,
        cipher_text_data_type,
        circuit_name
    )
    print(f"Generated TFHE circuit at {TFHE_CIRCUIT_DIR}")

    code = os.system(f"cd {TFHE_PROJECT_ROOT} && cargo fmt --all")
    if code != 0:
        raise ValueError(f"Failed to compile circom. Error code: {code}")

    # Step 4-a: run converted TFHE circuit
    st = time.time()
    outputs = run_tfhe_circuit(TFHE_PROJECT_ROOT)
    print(f"\n\n\n========= Computation has finished =========\n\n")
    print(f"Outputs: {outputs}")
    et = time.time()
    elapsed_time = et - st
    print('\n\n\n Generated Tfhe-rs Execution time:', elapsed_time, 'seconds')

    benchmark_dir = TFHE_PROJECT_ROOT / 'benchmark.json'
    with open(benchmark_dir, 'w') as fp:
        json.dump({"computation_time" : elapsed_time}, fp)

    # Step 4-b: run original TFHE circuit
    print(f"\n\n\nBENCH RAW MP-SPDZ circuit at {TFHE_RAW_CIRCUIT_DIR}")


    st = time.time()
    raw_outputs = run_tfhe_circuit(TFHE_RAW_PROJECT_ROOT)
    print(f"\n\n\n========= Raw Computation has finished =========\n\n")
    print(f"Outputs: {raw_outputs}")
    et = time.time()
    elapsed_time = et - st
    print('\n\n\nRAW Execution time:', elapsed_time, 'seconds')

    if outputs == raw_outputs:
        print("Output matches. Succeed.")
    else:
        print("Output doesn't match. Failed.")


if __name__ == '__main__':
    main()
