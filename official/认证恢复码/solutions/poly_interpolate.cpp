#include <NTL/GF2E.h>
#include <NTL/GF2X.h>
#include <NTL/GF2EX.h>
#include <NTL/vec_GF2E.h>
#include <NTL/ZZ.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

using namespace NTL;

GF2E ZZ_to_GF128(ZZ a) {
    GF2X Poly;
    Poly.SetLength(128);
    for (int i = 0; i < 128; i++) {
        if (bit(a, i) == 1) {
            SetCoeff(Poly, i);
        }
    }
    return to_GF2E(Poly);
}

void interpolate_polynomial(char* input_path, char* output_path, long maxPoints = 1<<16) {
    // read the input file
    std::ifstream input_file(input_path);
    if (!input_file.is_open()) {
        std::cerr << "Error: cannot open the input file" << std::endl;
        return;
    }
    std::cout << "Reading input file: " << input_path << std::endl;
    // the first line is the modulus for GF2E
    std::string modulus_str;
    if (!std::getline(input_file, modulus_str)) {
        std::cerr << "Error: invalid input format" << std::endl;
        return;
    }
    ZZ ModZZ = to_ZZ(modulus_str.c_str());
    int modbits = NumBits(ModZZ);
    GF2X ModPoly;
    ModPoly.SetLength(modbits);
    ModPoly.HexOutput = 1;
    for (int i = 0; i < modbits; i++) {
        if (bit(ModZZ, i) == 1) {
            // std::cout << "Setting coeff: " << i << std::endl;
            SetCoeff(ModPoly, i);
        }
    }
    GF2E::init(ModPoly);
    // std::cout << "GF2E modulus: " << GF2E::modulus() << std::endl;
    // lines
    vec_GF2E x, y;
    x.SetMaxLength(maxPoints);
    y.SetMaxLength(maxPoints);
    long numPoints = 0;
    std::string line;
    while (std::getline(input_file, line)) {
        std::istringstream iss(line);
        std::string x_str, y_str;
        if (!(iss >> x_str >> y_str)) {
            std::cerr << "Error: invalid input format" << std::endl;
            return;
        }
        x[numPoints] = ZZ_to_GF128(to_ZZ(x_str.c_str()));
        y[numPoints] = ZZ_to_GF128(to_ZZ(y_str.c_str()));
        // std::cout << "x: " << x[numPoints] << ", y: " << y[numPoints] << std::endl;
        numPoints++;
    }
    input_file.close();
    // interpolate the polynomial
    GF2EX L;
    x.SetLength(numPoints);
    y.SetLength(numPoints);
    L.SetLength(numPoints);
    interpolate(L, x, y);
    // write the output file
    std::ofstream output_file(output_path);
    if (!output_file.is_open()) {
        std::cerr << "Error: cannot open the output file" << std::endl;
        return;
    }
    std::cout << "Writing output file: " << output_path << std::endl;
    output_file << L << std::endl;
    output_file.close();
}

void local_test(long numPoints) {
    GF2X ModPoly;
    ModPoly.SetLength(129);
    ModPoly.HexOutput = 1;
    // modulus=x ** 128 + x ** 7 + x ** 2 + x + 1
    SetCoeff(ModPoly, 128);
    SetCoeff(ModPoly, 7);
    SetCoeff(ModPoly, 2);
    SetCoeff(ModPoly, 1);
    SetCoeff(ModPoly, 0);
    GF2E::init(ModPoly);
    std::cout << "GF2E modulus: " << GF2E::modulus() << std::endl;

    // define points
    vec_GF2E x, y;
    x.SetLength(numPoints);
    y.SetLength(numPoints);
    // generate ranom 128 points from urandom
    // start clock time
    double st = GetWallTime();
    for (int i = 0; i < numPoints; i++) {
        x[i] = ZZ_to_GF128(RandomBits_ZZ(128));
        y[i] = ZZ_to_GF128(RandomBits_ZZ(128));
    }
    double et = GetWallTime();
    std::cout << "Data generation time: " << et - st << " s" << std::endl;
    GF2EX L;
    L.SetLength(numPoints);
    st = GetWallTime();
    interpolate(L, x, y);
    // std::cout << "Interpolated polynomial: " << L << std::endl;
    et = GetWallTime();
    std::cout << "Interpolation time: " << et - st << " s" << std::endl;
    // check the interpolation
    for (int i = 0; i < numPoints; i++) {
        GF2E yi;
        eval(yi, L, x[i]);
        if (yi != y[i]) {
            std::cerr << "Error: interpolation failed" << std::endl;
            return;
        }
    }
    std::cout << "Interpolation test passed" << std::endl;
}

void data_test() {
    GF2X ModPoly;
    ModPoly.SetLength(129);
    ModPoly.HexOutput = 1;
    // modulus=x ** 128 + x ** 7 + x ** 2 + x + 1
    SetCoeff(ModPoly, 128);
    SetCoeff(ModPoly, 7);
    SetCoeff(ModPoly, 2);
    SetCoeff(ModPoly, 1);
    SetCoeff(ModPoly, 0);
    GF2E::init(ModPoly);
    std::cout << "GF2E modulus: " << GF2E::modulus() << std::endl;

    // define points
    vec_GF2E x, y;
    long numPoints = 2;
    x.SetLength(numPoints);
    y.SetLength(numPoints);
    x[0] = ZZ_to_GF128(to_ZZ("64594005364537620550212150841531907650"));
    x[1] = ZZ_to_GF128(to_ZZ("157509865643958166095935242667131453667"));
    y[0] = ZZ_to_GF128(to_ZZ("316434540707694254530007623262490325507"));
    y[1] = ZZ_to_GF128(to_ZZ("201191051208099574286740631118810974441"));
    std::cout << "x0: " << x[0] << ", y0: " << y[0] << std::endl;
    std::cout << "x1: " << x[1] << ", y1: " << y[1] << std::endl;
    GF2EX L;
    L.SetLength(numPoints);
    interpolate(L, x, y);
    // check the interpolation
    for (int i = 0; i < numPoints; i++) {
        GF2E yi;
        eval(yi, L, x[i]);
        if (yi != y[i]) {
            std::cerr << "Error: interpolation failed" << std::endl;
            return;
        }
    }
    std::cout << "Interpolation test passed" << std::endl;
    std::cout << "Interpolated polynomial: " << L << std::endl;
}

int main(int argc, char *argv[]) {
    // local_test(1<<10);
    // data_test();
    // return 0;
    long maxPoints = 1<<16;
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_path> <output_path> [<maxPoints>]" << std::endl;
        return 1;
    }
    else if (argc == 4) {
        maxPoints = std::stoi(argv[3]);
    }
    interpolate_polynomial(argv[1], argv[2], maxPoints);
    return 0;
}
