import json
import subprocess
import re
import numpy as np
from ml_tests.util import AveragePooling2DInt
from ml_tests.util import reshape_array

def main():
    process = subprocess.run(
        ['python3', 'main_ml_tests.py', 'AveragePooling2D'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    stdout = process.stdout

    outputs_match = re.search(r'Outputs:\s*(\{.*?\})', stdout, re.DOTALL)
    outputs_str = outputs_match.group(1)

    # Convert outputs_str to valid JSON format
    # Replace single quotes with double quotes
    outputs_str_json = outputs_str.replace("'", '"')
    outputs_dict = json.loads(outputs_str_json)

    # Extract indices and values, build a list of (indices, value) pairs
    indices_value_list = []
    for key, value in outputs_dict.items():
        indices = list(map(int, re.findall(r'\d+', key)))
        indices_value_list.append((indices, float(value)))

    # Sort the indices_value_list based on indices
    indices_value_list.sort(key=lambda x: x[0])

    # Extract the values into a flat list
    values_list = [value for indices, value in indices_value_list]

    # Descale the values
    values_list = [value / 2**10 for value in values_list]

    dimensions = [2, 2, 3]

    real_output = reshape_array(values_list, dimensions)

    # Read input data for 'AveragePooling2DInt' function
    with open('ml_tests/AveragePooling2D/averagePooling2D_input.json', 'r') as f:
        data = json.load(f)

    input_data = data['in_unchanged']

    # Compute the correct output
    correct_output = AveragePooling2DInt(5, 5, 3, 2, 2, input_data)

    print(f"Correct output: {correct_output}\n")
    print(f"Real output: {real_output}\n")

    correct_output_np = np.array(correct_output, dtype=float)
    real_output_np = np.array(real_output, dtype=float)

    difference = np.abs(correct_output_np - real_output_np)

    print(f"Difference between outputs: \n{difference}")

if __name__ == "__main__":
    main()