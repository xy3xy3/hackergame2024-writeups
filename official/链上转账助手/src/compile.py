from solcx import compile_files
import json

for i in 1, 2, 3:
    compiled_sol = compile_files(
        f'challenge{i}.sol',
        output_values=['abi', 'bin'],
        optimize=True,
        optimize_runs=999999,
        solc_version='0.8.28',
    )
    contract_interface = compiled_sol[f'challenge{i}.sol:BatchTransfer']
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']
    json.dump((bytecode, abi), open(f'contract{i}.json', 'w'))
