# Circom-tfhe-rs

Circom-tfhe-rs enables users to generate a TFHE circuit that corresponds to the arithmetization of a Circom circuit. In simpler terms, it translates Circom circuits into their TFHE equivalents. Circom code is compiled into an arithmetic circuit using circom-2-arithc and then translated gate by gate to the corresponding tfhe-rs operators.

**NOTE:** Now circom-2-arithc also conveniently outputs the Bristol format with corresponding circuit_info (hence the json_arbistol is not necessary anymore).



## Supported Circom  Op

| Op                             |   FheUint  |  FheInt  |
| ------------------------------ | :-------:  | :-------:|
| `+`      Addition              |     ✅     |     ✅     |
| `/`      Division              |     ✅     |     ✅     |
| `==`     Equality              |     ✅     |     ✅     |
| `>`      Greater Than          |     ✅     |     ✅     |
| `>=`     Greater Than or Equal |     ✅     |     ✅     |
| `<`      Less Than             |     ✅     |     ✅     |
| `<=`     Less Than or Equal    |     ✅     |     ✅     |
| `*`   Multiplication           |     ✅     |     ✅     |
| `!=` Not Equal                 |     ✅     |     ✅     |
| `-`  Subtraction               |     ✅     |     ✅     |
| `**` Exponentiation            |     ❌     |     ❌     |
| `<<` Shift Left                |     ✅     |     ❌     |
| `>>` Shift Right               |     ✅     |     ❌     |
| `^`  Bitwise XOR               |     ✅     |     ✅     |
| `\|` Bitwise OR                |     ✅     |     ✅     |
| `&`  Bitwise AND               |     ✅     |     ✅     |
| `%`  Modulo                    |     ✅     |     ✅     |



## Structure

- [circom-2-arithc](https://github.com/namnc/circom-2-arithc) - we are using the latest version.
- [tfhe-rs](https://github.com/zama-ai/tfhe-rs) - supports the arithmetization on tfhe
- [main.py](./main.py) - the main script to run the circom-tfhe. It does the following:
  - Compiles the Circom code to the arithmetic circuit with `circom-2-arithc`.
  - Generates tfhe-rs program by converting bristol fashion circuit.
  - Performs the computation using tfhe-rs.
- [examples](./examples) - example circuits to run with circom-tfhe.



## Installation

### Clone the repo

```bash
git clone https://github.com/Vishalkulkarni45/circom-tfhe-rs
git clone https://github.com/namnc/circom-2-arithc
```

### Build circom-2-arithc

Go to the circom-2-arithc submodule directory:

```bash
cd circom-2-arithc
```

Initialize the .env file:

```bash
touch .env
vim .env
```

Build the compiler:

```bash
cargo build --release
```



## How to run

We have two examples available:

- [ops_tests](./examples/ops_tests/) - a benchmark of supported operations
- [naive_search](./examples/naive_search/) - a benchmark of naive search

For both the examples ,We successfully executed them for FheUint8, FheUint16, and FheUint64 on a 4-core machine with 16GB of RAM, but encountered memory limitations when attempting FheUint128.

In both examples, you will find the following files in each example directory:

- `circuit.circom` - the circom code representing the circuit
- `{circuit_name}.py` - automated generator for input files and `raw_circuit` tfhe-rs program

You can run these examples by following the instructions in the root directory.

```bash
#Before running this you need to change the raw tfhe code plain and cipher text data type manunal
python main.py {circuit_name} {plain_text_data_type} 
```
- `{circuit_name}` is the name of the circuit you want to run. Can either be `ops_tests` or `naive_search`.
- Intermediate files will be stored in the `outputs/{circuit_name}` directory.
- Outputs are directly printed to the console.



## How it works

1. Generate Rust directory in the `outputs` folder; `outputs/{circuit_name}` and `outputs/{circuit_name}_raw`

   - If the directory exists, it deletes the directory and makes new directory.


2. Add the necessary dependencies in `Cargo.toml` in each Rust directory.
3. For existing circom circuit, run circom-2-arithc.
4. Run python script in `examples/{circuit_name}/`
   - It generates `raw_circuit` tfhe-rs code, `input.json`
   - After generating `input.json`, make a new file `input_struct.json` which has different format.
   - After generating `raw_circuit` tfhe-rs code, copy it into `outputs/{circuit_name}_raw`
   - Copy `input.json` and `input_struct.json` in `outputs/{circuit_name}` and `outputs/{circuit_name}_raw`
5. Using bristol fashion circuit, generate tfhe-rs code.
   - It divides the operation into two folder: client and server.
   - Client code is responside for encrypting the inputs and decrypting the output
   - Server code handles performing operations on the encrypted inputs.
6. Run converted tfhe-rs code, and compare it with model tfhe-rs code.
   - It compares the output of the generated TFHE circuit with that of the manually created TFHE circuit.
   - It also compares the output of the generated TFHE circuit with the functionality executed using unencrypted methods (via native Rust , which is present in circuit_name_raw folder)
