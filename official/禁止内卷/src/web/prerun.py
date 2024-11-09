import json
import random

# flag = "Submit your payload to get the real flag!"

with open("/flag") as f:
    flag = f.read().strip()
assert len(flag) < 500

answers = []

for i in flag:
    answers.append(ord(i) - 65)

for _ in range(500 - len(flag)):
    answers.append(random.randint(0, 100))

with open("answers.json", "w") as f:
    json.dump(answers, f)

# print(answers)
