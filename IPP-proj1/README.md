Documentation of 1. part of IPP project implementation 2022/2023
Name and surname: David Sklenář
Login: xsklen14

Submitted script parse.php supports base functionality. It has been implemented without OOP
approach, but it is still relatively easy to expand it in case of new features.

## Parsing
The input program is parsed line by line using combination of regular expressions and logic of
program. Each line is first preprocessed by trimming whitespaces from each side of line, removing
comments and separating line by whitespaces (or tabs) to array. Then the first element is array,
which should be opcode of instruction is uppercased and looked for in switch case. Based on given
opcode, other elements in array are processed. At last, generate functions are called in correct order
and all of this is concatenated into output variable, which is echoed at STDOUT before program end.
In case of wrong input, program ends with appropriate exit code and error message.

## Program
Program is separated into functions. Validate functions are used for regex matching of input, if
instructions and its parameters are correct. Generate functions are basically used for xml generation.
Main function contains switch. Overall this program only parses input in pseudo-assembly to XML format, that is later processed by secont part of this project (interpreter.py)