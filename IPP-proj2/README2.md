Documentation of 1. part of IPP project documentation 2022/2023

Name and surname: David Sklenář

Login: xsklen14

# Documentation of 2. part of IPP project

## Introduction
This project is a part of IPP course at FIT BUT. The goal of this project is to create a simple interpreter for a language called IPPcode23. The language is a simple assembly language with a few instructions and is defined in a XML file. The interpreter is written in Python 3.10.11.

## Requirements and used libraries
- Python 3.10.11
- Python libraries:
    - sys
    - re
    - xml.etree.ElementTree

## Usage
The program is run from the command line and takes 1 or 2 arguments. 
The first argument is the path to the XML file with the IPPcode23 code, second is path to file with program inputs.
If one of parameters in not specified, the program reads the input from the standard input, but at least one parameter has to be specified.
If the second argument is not specified, the program reads the input from the standard input. 
The program writes the output to the standard output. The program writes the error messages to the standard error output. The program returns 0 if the program was executed successfully or multiple error codes based on what failed.

__Examples of running the program:__
``` bash

python3.10 interpret.py --source=example.xml --input=example.in

python3.10 interpret.py --source=example.xml

python3.10 interpret.py --source=example.xml < example.in

python3.10 interpret.py --input=example.in < example.xml

```

## Example of XML structure

__Example of XML file:__
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<program language="IPPcode23">
    <instruction order="1" opcode="JUMP">
        <arg1 type="label">endd</arg1>
    </instruction>
    <instruction order="2" opcode="LABEL">
        <arg1 type="label">foo</arg1>
    </instruction>
    <instruction order="3" opcode="WRITE">
        <arg1 type="string">Oh,yeah,brother!</arg1>
    </instruction>
    <instruction order="5" opcode="RETURN"/>
    <instruction order="6" opcode="LABEL">
        <arg1 type="label">endd</arg1>
    </instruction>
    <instruction order="7" opcode="CALL">
        <arg1 type="label">foo</arg1>
    </instruction>
</program>
```

## Implementation
According to the project description, the program should use as much OO principles as possible. 
At the start of program, the instance of Interpret class is created. This class is used to parse the arguments, check the argument and parse input xml file into Instructions.
When everything is correctly parsed, the instance of ExecuteProgram class is created and the program is executed.
The ExecuteProgram class is handling program execution, it contains implementation of every instruction and controls the flow of the program.

Then the program contains classes for instructions, arguments, frames, stacks and variables. These are used to represent the instructions and their arguments, frames, stacks and variables.




### Interpret class
__Definition:__
``` python
class Interpret:
    def __init__(self):
        self.input_file = ""
        self.source_file = ""
        self.tree = None
        self.root = None
        self.INSTRUCTIONS = ("MOVE", "CREATEFRAME", "PUSHFRAME", "POPFRAME",
                             "DEFVAR", "CALL", "RETURN", "PUSHS",
                             "POPS", "ADD", "SUB", "MUL",
                             "IDIV", "LT", "GT", "EQ",
                             "AND", "OR", "NOT", "INT2CHAR",
                             "STRI2INT", "READ", "WRITE", "CONCAT",
                             "STRLEN", "GETCHAR", "SETCHAR", "TYPE",
                             "LABEL", "JUMP", "JUMPIFEQ", "JUMPIFNEQ",
                             "EXIT", "DPRINT", "BREAK")
        self.instruction_list = []
```
This class is used to parse the arguments, check the argument and parse input xml file into Instructions.
It serves as a main class of the program, controls the program execution.

__Methods:__
- do_magic() - main method of the class, it controls the program execution
- read_files() - sets the input and source files according to the arguments
- arg_parse() - parses the arguments
- check_xml() - checks if the xml file is valid
- check_instruction_args() - checks if the arguments of the instructions are valid, does basic type checking
- parse_xml() - parses the xml file into Instructions

### ExecuteProgram class
__Definition:__
``` python
class ExecuteProgram:
    def __init__(self, instructions, input_file):
        self.instructions = instructions
        self.instruction_pointer = 0
        self.instruction = None
        self._GF_frame = Frame()
        self._TF_frame = None  # it is defined only when it is created or poped
        self._labels = {}
        self._frames_stack = Stack()
        self._data_stack = Stack()
        self._call_stack = Stack()
        self._input_file = input_file
```
Executes the instructions from the list of instructions.
Controls flow of the executing program.

__Methods:__
- match_labels() - does a first pass through the instructions and matches the labels with their order
- _translate_string(string) - converts the string to the correct format for printing
- _get_var(var) - returns the variable from the frame
- _arithmetics(instruction, operation) - shared method for arithmetic operations
- _and_or(instruction, operation) - shared method for and and or operations
- _compare(instruction, operation) - shared method for comparison operations
- execute() - main method of the class, it controls the input program execution, decides which instruction should be executed
- at last this class contains implementation of every instruction

### Instruction class
__Definition:__
``` python
class Instruction:
    def __init__(self, opcode, order):
        self.opcode = opcode
        self.order = order
        self.args = []
```
Represents one instruction from the input xml file.

__Methods:__
- add_arg(arg) - adds Argument object to the instruction
- get_arg(index) - returns the Argument object at the specified index
- get_args() - returns the list of arguments
- get_opcode() - returns the opcode of the instruction

### Argument class
__Definition:__
``` python
class Argument:
    def __init__(self, typ, data):
        self.typ = typ
        self.data = data
```
Represents one argument from the input xml file.

__Methods:__
- get_type() - returns the type of the argument
- get_data() - returns the data of the argument
- convert_data() - converts the data from XML to the correct format, etc. if the argument is a type of int, it converts it to int

### Variable class
__Definition:__
``` python
class Variable:
    def __init__(self, name, typ, value):
        self.name = name  # contains also frame
        self.type = typ
        self.value = value
```
Represents one variable from the input xml file.

__Methods:__
- get_name() - returns the name of the variable
- get_type() - returns the type of the variable
- get_value() - returns the value of the variable
- set_value(value) - sets the value of the variable
- set_type(typ) - sets the type of the variable
- set_name(name) - sets the name of the variable

### Frame class
__Definition:__
``` python
class Frame:
    def __init__(self):
        self.variables = {}
```
Represents one frame from the input xml file.
Serves as a wrapper for dictionary of variables.

__Methods:__
- add_variable(var) - adds Variable object to the frame
- get_variable(name) - returns the Variable object with the specified name
- get_variables() - returns the list of variables

### Stack class
__Definition:__
``` python
class Stack:
    def __init__(self):
        self.stack = []
```
Represents one stack from the input xml file.
Serves as a wrapper for list of variables.

__Methods:__
- push(var) - adds Variable object to the stack
- pop() - returns the Variable object from the top of the stack
- top() - returns the Variable object from the top of the stack without removing it
- is_empty() - returns True if the stack is empty, False otherwise