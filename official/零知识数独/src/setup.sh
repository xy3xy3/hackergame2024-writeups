#!/bin/bash

if [ "$#" -lt 1 ] || [ "$#" -gt 4 ]; then
    echo "Usage: $0 <circom_filename> [output_directory] [groth16_ptau] [OPTIMATION]"
    exit 1
fi

CIRCOM_FILE=$1
OUTPUT_DIR=${2:-groth16}
GROTH16_FINAL_PTAU=${3:-pot12_final.ptau}
OPTIMATION=${4:-O2}

mkdir -p "$OUTPUT_DIR"

echo "circom "$CIRCOM_FILE" --r1cs --sym --wasm --$OPTIMATION -o "$OUTPUT_DIR/""
circom "$CIRCOM_FILE" --r1cs --sym --wasm --$OPTIMATION -o "$OUTPUT_DIR/"
if [ $? -eq 0 ]; then
    echo "Successful."
else
    echo "Command failed."
    exit 1
fi

# Start the powersoftau process
CLEAN_CIRCOM_FILE=$(echo "$CIRCOM_FILE" | sed 's/@/\@/g' | sed 's/=/\=/g' | sed 's/\.[^.]*$//')

if [ ! -f "$GROTH16_FINAL_PTAU" ]; then
    echo "The final powers of tau file does not exist. Generating locally. This may take a while."
    echo "snarkjs powersoftau new bn128 15 pot12_0000.ptau"
    snarkjs powersoftau new bn128 15 pot12_0000.ptau -v > /dev/null
    if [ $? -eq 0 ]; then
        echo "Successful."
    else
        echo "Command failed."
        exit 1
    fi

    echo "snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v"
    snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Successful."
    else
        echo "Command failed."
        exit 1
    fi

    echo "snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v"
    snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v > /dev/null
    if [ $? -eq 0 ]; then
        echo "Successful."
    else
        echo "Command failed."
        exit 1
    fi
    GROTH16_FINAL_PTAU="pot12_final.ptau"
    rm pot12_0000.ptau pot12_0001.ptau
fi


# Groth16 Circuit Setup
echo "snarkjs groth16 setup "${OUTPUT_DIR}/${CLEAN_CIRCOM_FILE}.r1cs" "${GROTH16_FINAL_PTAU}" "${CLEAN_CIRCOM_FILE}"0.zkey"
snarkjs groth16 setup "${OUTPUT_DIR}/${CLEAN_CIRCOM_FILE}.r1cs" "${GROTH16_FINAL_PTAU}" "${CLEAN_CIRCOM_FILE}"0.zkey

if [ $? -eq 0 ]; then
    echo "Successful."
else
    echo "Command failed."
    exit 1
fi

# Contribute to the setup
echo "snarkjs zkey contribute "${CLEAN_CIRCOM_FILE}"0.zkey circuit1.zkey --name="1st Contributor Name" -v"
snarkjs zkey contribute "${CLEAN_CIRCOM_FILE}"0.zkey "${CLEAN_CIRCOM_FILE}".zkey --name="1st Contributor Name" -v
if [ $? -eq 0 ]; then
    echo "successful."
else
    echo "Command failed."
    exit 1
fi

rm "${CLEAN_CIRCOM_FILE}"0.zkey
mv "${OUTPUT_DIR}/${CLEAN_CIRCOM_FILE}_js/${CLEAN_CIRCOM_FILE}.wasm" "./"
rm -rf "${OUTPUT_DIR}"

# Export the verification key
echo "snarkjs zkey export verificationkey "${CLEAN_CIRCOM_FILE}".zkey verification_key.json"
snarkjs zkey export verificationkey "${CLEAN_CIRCOM_FILE}".zkey verification_key.json
if [ $? -eq 0 ]; then
    echo "successful."
else
    echo "Command failed."
    exit 1
fi
echo "Done."