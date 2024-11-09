const snarkjs = require('snarkjs');

async function generateProof(solvedGrid, unsolvedGrid) {
    try {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            { solved_grid: solvedGrid, unsolved_grid: unsolvedGrid },
            "../attachment/sudoku.wasm",
            "../attachment/sudoku.zkey"
        );
        console.log(JSON.stringify({ proof, publicSignals }));
    } catch (err) {
        console.error("Error generating proof:", err);
    }
    finally {
        process.exit();
    }
}

const args = process.argv.slice(2);
const solvedGrid = JSON.parse(args[0]);
const unsolvedGrid = JSON.parse(args[1]);
generateProof(solvedGrid, unsolvedGrid);