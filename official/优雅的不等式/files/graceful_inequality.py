import sympy

x = sympy.Symbol('x')
allowed_chars = "0123456789+-*/()x"
max_len = 400

# Example input for difficulty 0:   4*((1-x**2)**(1/2)-(1-x))

for difficulty in range(0, 40):
    if difficulty == 0:
        p, q = 2, 1
    elif difficulty == 1:
        p, q = 8, 3
    else:
        a = (2**(difficulty * 5))
        q = sympy.randprime(a, a * 2)
        p = sympy.floor(sympy.pi * q)
    p = sympy.Integer(p)
    q = sympy.Integer(q)
    if q != 1:
        print("Please prove that pi>={}/{}".format(p, q))
    else:
        print("Please prove that pi>={}".format(p))
    f = input("Enter the function f(x): ").strip().replace(" ", "")
    assert len(f) <= max_len, len(f)
    assert set(f) <= set(allowed_chars), set(f)
    assert "//" not in f, "floor division is not allowed"
    f = sympy.parsing.sympy_parser.parse_expr(f)
    assert f.free_symbols <= {x}, f.free_symbols
    # check if the range integral is pi - p/q
    integrate_result = sympy.integrate(f, (x, 0, 1))
    assert integrate_result == sympy.pi - p / q, integrate_result
    # verify that f is well-defined and real-valued and non-negative on [0, 1]
    domain = sympy.Interval(0, 1)
    assert sympy.solveset(f >= 0, x, domain) == domain, "f(x)>=0 does not always hold on [0, 1]"
    print("Q.E.D.")
    if difficulty == 1:
        print(open("flag1").read())

# finished all challenges
print(open("flag2").read())
