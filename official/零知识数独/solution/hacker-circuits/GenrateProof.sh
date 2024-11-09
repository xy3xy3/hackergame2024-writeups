#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <circom_filename> <input_json_file> <verification_key> [OPTIMATION]"
    exit 1
fi

CIRCOM_FILE=$1
INPUT_JSON_FILE=$2
VKEY_FILE=$3
OUTPUT_DIR="groth16"
OPTIMATION=${4:-O2}
CLEAN_CIRCOM_FILE=$(echo "$CIRCOM_FILE" | sed 's/@/\@/g' | sed 's/=/\=/g' | sed 's/\.[^.]*$//')

mkdir -p "$OUTPUT_DIR"

echo "circom "$CIRCOM_FILE" --r1cs --sym --wasm --$OPTIMATION -o "$OUTPUT_DIR/""
circom "$CIRCOM_FILE" --r1cs --sym --wasm --$OPTIMATION -o "$OUTPUT_DIR/"
if [ $? -eq 0 ]; then
    echo "Successful."
else
    echo "Command failed."
    exit 1
fi

# generate the witness
node "${OUTPUT_DIR}/${CLEAN_CIRCOM_FILE}_js/generate_witness.js" "${OUTPUT_DIR}/${CLEAN_CIRCOM_FILE}_js/${CLEAN_CIRCOM_FILE}.wasm" "$INPUT_JSON_FILE" witness.wtns
rm -rf "${OUTPUT_DIR}"

echo "snarkjs groth16 prove sudoku.zkey witness.wtns proof.json public.json"
snarkjs groth16 prove sudoku.zkey witness.wtns proof.json public.json
if [ $? -eq 0 ]; then
    echo "successful."
else
    echo "Command failed."
    exit 1
fi

# Verify the proof
echo "snarkjs groth16 verify "${VKEY_FILE}" public.json proof.json"
snarkjs groth16 verify "${VKEY_FILE}" public.json proof.json
if [ $? -ne 0 ]; then
    echo "Failed to verify proof"
    exit 1
fi

