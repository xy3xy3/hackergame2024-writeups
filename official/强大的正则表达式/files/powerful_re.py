import re
import random

# pip install libscrc
import libscrc

allowed_chars = "0123456789()|*"
max_len = 1000000
num_tests = 300

difficulty = int(input("Enter difficulty level (1~3): "))
if difficulty not in [1, 2, 3]:
    raise ValueError("Invalid difficulty level")

regex_string = input("Enter your regex: ").strip()

if len(regex_string) > max_len:
    raise ValueError("Regex string too long")

if not all(c in allowed_chars for c in regex_string):
    raise ValueError("Invalid character in regex string")

regex = re.compile(regex_string)

for i in range(num_tests):
    expected_result = (i % 2 == 0)
    while True:
        t = random.randint(0, 2**64)  # random number for testing
        if difficulty == 1:
            test_string = str(t)  # decimal
            if (t % 16 == 0) == expected_result:  # mod 16
                break
        elif difficulty == 2:
            test_string = bin(t)[2:]  # binary
            if (t % 13 == 0) == expected_result:  # mod 13
                break
        elif difficulty == 3:
            test_string = str(t)  # decimal
            if (libscrc.gsm3(test_string.encode()) == 0) == expected_result:  # crc
                break
        else:
            raise ValueError("Invalid difficulty level")
    regex_result = bool(regex.fullmatch(test_string))
    if regex_result == expected_result:
        print("Pass", test_string, regex_result, expected_result)
    else:
        print("Fail", test_string, regex_result, expected_result)
        raise RuntimeError("Failed")

print(open(f"flag{difficulty}").read())
