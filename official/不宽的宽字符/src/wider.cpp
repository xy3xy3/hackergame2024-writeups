#include <iostream>
#include <fstream>
#include <cctype>
#include <string>
#include <windows.h>

int main()
{
    std::wcout << L"Enter filename. I'll append 'you_cant_get_the_flag' to it:" << std::endl;

    // Get the console input and output handles
    HANDLE hConsoleInput = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);

    if (hConsoleInput == INVALID_HANDLE_VALUE || hConsoleOutput == INVALID_HANDLE_VALUE)
    {
        // Handle error – we can't get input/output handles.
        return 1;
    }

    DWORD mode;
    GetConsoleMode(hConsoleInput, &mode);
    SetConsoleMode(hConsoleInput, mode | ENABLE_PROCESSED_INPUT);

    // Buffer to store the wide character input
    char inputBuffer[256] = { 0 };
    DWORD charsRead = 0;

    // Read the console input (wide characters)
    if (!ReadFile(hConsoleInput, inputBuffer, sizeof(inputBuffer), &charsRead, nullptr))
    {
        // Handle read error
        return 2;
    }

    // Remove the newline character at the end of the input
    if (charsRead > 0 && inputBuffer[charsRead - 1] == L'\n')
    {
        inputBuffer[charsRead - 1] = L'\0'; // Null-terminate the string
        charsRead--;
    }

    // Convert to WIDE chars
    wchar_t buf[256] = { 0 };
    MultiByteToWideChar(CP_UTF8, 0, inputBuffer, -1, buf, sizeof(buf) / sizeof(wchar_t));

    std::wstring filename = buf;

    // Haha!
    filename += L"you_cant_get_the_flag";

    std::wifstream file;
    file.open((char*)filename.c_str());

    if (file.is_open() == false)
    {
        std::wcout << L"Failed to open the file!" << std::endl;
        return 3;
    }

    std::wstring flag;
    std::getline(file, flag);

    std::wcout << L"The flag is: " << flag << L". Congratulations!" << std::endl;

    return 0;
}
