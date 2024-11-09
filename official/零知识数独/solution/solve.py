from sage.games.sudoku import Sudoku
from sage.all import ZZ
import requests
import json
import subprocess

token = "your_token"
sessionID = "your_sessionID_in_zksudoku_cookie"

chall = "http://202.38.93.141:21112/zk-puzzle"
verify = "http://202.38.93.141:21112/zk-check"

header = {
    "Content-Type": "application/json",
    "Cookie": f"zksudoku_token={token}; sessionID={sessionID}",
}

def run_snarkjs_proof(solved_grid, unsolved_grid):
    solved_grid_str = json.dumps(solved_grid)
    unsolved_grid_str = json.dumps(unsolved_grid)
    try:
        # print(f"Running Node.js script: node generate_proof.js {solved_grid_str} {unsolved_grid_str}")
        result = subprocess.run(
            ["node", "generate_proof.js", solved_grid_str, unsolved_grid_str],
            capture_output=True,
            text=True,
            check=True
        )
        
        output = result.stdout.strip()
        proof_data = json.loads(output)
        proof = proof_data['proof']
        public_signals = proof_data['publicSignals']
        return proof, public_signals

    except subprocess.CalledProcessError as e:
        print(f"Error executing Node.js script: {e}")
        print(e.output)
        return None, None
    
def submit_proof(url, proof, public_signals, difficulty):
    data = {
        "proof": proof,
        "publicSignals": public_signals,
        "difficulty": difficulty
    }
    res = requests.post(url, json=data, headers=header)
    return res.json()

def getpuzzle(url):
    res = requests.get(url, headers=header)
    if "set-cookie" in res.headers:
        sessionId = res.headers['set-cookie'].split(";")[0]
        print(f"Session ID: {sessionId}")
        header['cookie'] = sessionId
    return res.json()


sudoku = getpuzzle(chall)
puzzle = sudoku['puzzle']
puzzle_string = ''.join([str(x) if x!=0 else "." for x in puzzle])
sudoku_puzzle = Sudoku(puzzle_string)
solu = next(sudoku_puzzle.solve())
solu = [int(x) for x in solu.to_list()]
open("input.json", "w").write(json.dumps({"solved_grid": solu, "unsolved_grid": puzzle}))
proof, public_signals = run_snarkjs_proof(solu, puzzle)
print("Submitting proof")
flag_result1 = submit_proof(verify, proof, public_signals, sudoku['difficulty'])
print(f"{flag_result1 = }")

impossibleSudoku = {
  "puzzle": [
    9, 0, 0, 0, 0, 0, 1, 0, 0,
    8, 0, 0, 0, 0, 0, 2, 0, 0,
    7, 0, 0, 0, 0, 0, 3, 0, 0,
    0, 0, 1, 0, 0, 0, 0, 0, 6,
    0, 2, 0, 0, 0, 0, 0, 7, 0,
    0, 0, 3, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 6, 0,
    0, 0, 2, 0, 0, 0, 0, 0, 7,
    0, 3, 0, 0, 0, 0, 0, 0, 0,
  ],
  "solution": [
    9, 6,-3, 8, 3, 4, 1, 5, -4,
    8, 4,-4, 1, 5, 6, 2,-1,-2,
    7,-1,-2, 2, 9, -4, 3, 4,-3,
    4, 7, 1, 3, 2, 5, 8, 9, 6,
    5, 2, 8, 6, 1, 9, 4, 7, 3,
    6, 9, 3, 4, 7, 8, 5, 1, 2,
    -4, 1, 4, 5, 8, 2,-1, 6, 9,
   -1, 5, 2, 9, 4, 3, -4, 8, 7,
   -2, 3, 9, 7, 6, 1,-3, 2, 4,
],
  "difficulty": 'impossible'
}

puzzle = impossibleSudoku['puzzle']
solu = impossibleSudoku['solution']
puzzle_string = ''.join([str(x) if x!=0 else "." for x in puzzle])
public_signals = json.loads(open("./hacker-circuits/public.json").read())
proof = json.loads(open("./hacker-circuits/proof.json").read())
flag_result2 = submit_proof(verify, proof, public_signals, impossibleSudoku['difficulty'])
print(f"{flag_result2 = }")