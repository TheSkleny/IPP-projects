import re
import sys
import xml.etree.ElementTree as ET


def stderr_print(message, exit_code):
    sys.stderr.write(message + "\n")
    exit(exit_code)


class Instruction:

    def __init__(self, opcode, order):
        self.opcode = opcode
        self.order = order
        self.args = []

    def add_arg(self, arg):
        self.args.append(arg)

    def get_arg(self, index):
        return self.args[index]

    def get_args(self):
        return self.args


class Argument:
    def __init__(self, typ, data):
        self.typ = typ
        self.data = data
        
    def get_type(self):
        return self.typ
    
    def get_data(self):
        return self.data


class Variable:
    def __init__(self, name, typ, value):
        self.name = name  # contains also frame
        self.type = typ
        self.value = value

    def get_value(self):
        return self.value

    def get_type(self):
        return self.type

    def get_name(self):
        return self.name


class Frame:
    def __init__(self):
        self.variables = {}

    def add_variable(self, variable):  # variable is Variable object, name is string in format GF@var
        self.variables[variable.get_name()] = variable

    def get_variable(self, name):  # returns Variable object
        return self.variables[name]


class Stack:
    def __init__(self):
        self.stack = []

    def push(self, item):
        self.stack.append(item)

    def pop(self):
        return self.stack.pop()


class ExecuteProgram:
    def __init__(self, instructions):
        self.instructions = instructions
        self.instruction_index = 0
        self.instruction = None
        self._GF_frame = Frame()
        self._LF_frame = None  # definuje se az kdyz se ma stvorit
        self._TF_frame = None  # definuje se az kdyz se ma stvorit
        self._labels = {}
        self._frames_stack = Stack()
        self._data_stack = Stack()
        
    def _get_var(self, name):
        if name[0] == "G":
            return self._GF_frame.get_variable(name)
        elif name[0] == "L":
            try:
                return self._LF_frame.get_variable(name)
            except AttributeError:
                stderr_print("ERR: Local frame not defined", 55)
        elif name[0] == "T":
            try:
                return self._TF_frame.get_variable(name)
            except AttributeError:
                stderr_print("ERR: Temporary frame not defined", 55)
        else:
            stderr_print("ERR: Invalid variable name", 32)
    
    def execute(self):
        for instr in self.instructions:
            match instr.opcode:
                case "MOVE":
                    self.move()
                case "CREATEFRAME":
                    self.create_frame()
                case "PUSHFRAME":
                    self.push_frame()
                case "POPFRAME":
                    self.pop_frame()
                case "DEFVAR":
                    self.def_var()
                case "CALL":
                    self.call()
                case "RETURN":
                    self.return_()
                case "PUSHS":
                    self.pushs()
                case "POPS":
                    self.pops()
                case "ADD":
                    self.add()
                case "SUB":
                    self.sub()
                case "MUL":
                    self.mul()
                case "IDIV":
                    self.idiv()
                case "LT":
                    self.lt()
                case "GT":
                    self.gt()
                case "EQ":
                    self.eq()
                case "AND":
                    self.and_()
                case "OR":
                    self.or_()
                case "NOT":
                    self.not_()
                case "INT2CHAR":
                    self.int2char()
                case "STRI2INT":
                    self.stri2int()
                case "READ":
                    self.read()
                case "WRITE":
                    self.write(instr)
                case "CONCAT":
                    self.concat()
                case "STRLEN":
                    self.strlen()
                case "GETCHAR":
                    self.getchar()
                case "SETCHAR":
                    self.setchar()
                case "TYPE":
                    self.type_()
                case "LABEL":
                    self.label()
                case "JUMP":
                    self.jump()
                case "JUMPIFEQ":
                    self.jumpifeq()
                case "JUMPIFNEQ":
                    self.jumpifneq()
                case "EXIT":
                    self.exit()
                case "DPRINT":
                    self.dprint()
                case "BREAK":
                    self.break_()
                case _:  # default
                    stderr_print("ERR: Invalid instruction", 32)

    def move(self):
        raise NotImplementedError

    def create_frame(self):
        raise NotImplementedError

    def push_frame(self):
        raise NotImplementedError

    def pop_frame(self):
        raise NotImplementedError

    def def_var(self):
        raise NotImplementedError

    def call(self):
        raise NotImplementedError

    def return_(self):
        raise NotImplementedError

    def pushs(self):
        raise NotImplementedError

    def pops(self):
        raise NotImplementedError

    def add(self):
        raise NotImplementedError

    def sub(self):
        raise NotImplementedError

    def mul(self):
        raise NotImplementedError

    def idiv(self):
        raise NotImplementedError

    def lt(self):
        raise NotImplementedError

    def gt(self):
        raise NotImplementedError

    def eq(self):
        raise NotImplementedError

    def and_(self):
        raise NotImplementedError

    def or_(self):
        raise NotImplementedError

    def not_(self):
        raise NotImplementedError

    def int2char(self):
        raise NotImplementedError

    def stri2int(self):
        raise NotImplementedError

    def read(self):
        raise NotImplementedError

    def write(self, instruction):
        if instruction.get_arg(0).get_type() == "bool":
            print("true" if instruction.get_arg(0).data == "true" else "false", end="")
        elif instruction.get_arg(0).get_type() == "nil":
            print("", end="")
        elif instruction.get_arg(0).get_type() == "var":
            var = self._get_var(instruction.get_arg(0).data)
            if var.get_type() == "bool":
                print("true" if var.get_value() == "true" else "false", end="")
            elif var.get_type() == "nil":
                print("", end="")
            else:
                print(var.get_value(), end="")
        else:
            print(instruction.get_arg(0).data, end="")
    def concat(self):
        raise NotImplementedError

    def strlen(self):
        raise NotImplementedError

    def getchar(self):
        raise NotImplementedError

    def setchar(self):
        raise NotImplementedError

    def type_(self):
        raise NotImplementedError

    def label(self):
        raise NotImplementedError

    def jump(self):
        raise NotImplementedError

    def jumpifeq(self):
        raise NotImplementedError

    def jumpifneq(self):
        raise NotImplementedError

    def exit(self):
        raise NotImplementedError

    def dprint(self):
        raise NotImplementedError

    def break_(self):
        raise NotImplementedError


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
        pass

    def do_magic(self):
        self.arg_parse()
        self.read_files()
        self.check_xml()
        self.parse_xml()
        execute = ExecuteProgram(self.instruction_list)
        execute.execute()
    def read_files(self):
        if self.source_file == "":
            self.tree = ET.parse(sys.stdin, ET.XMLParser(encoding="utf-8"))
        else:
            try:
                self.tree = ET.parse(self.source_file, ET.XMLParser(encoding="utf-8"))
            except Exception:
                stderr_print("ERR: XML file has invalid format", 31)
        if self.input_file == "":
            self.input_file = sys.stdin
        else:
            try:
                self.input_file = open(self.input_file, "r")
            except FileNotFoundError:
                stderr_print("ERR: Nonexistent input file", 31)

    def arg_parse(self):
        for arg in sys.argv[1:]:
            if re.match(r'--input=.*', arg):
                self.input_file = arg.split('=')[1]
            elif re.match(r'--source=.*', arg):
                self.source_file = arg.split('=')[1]
            elif arg == "--help":
                print("\nUsage: python interpret_bad.py [--help] [--source=source_file / --input=input_file]")
                print("--source=source_file - path to XML source file")
                print("--input=input_file - path to file with user inputs (can be empty)")
                print("--help - print this help")
                print(
                    "At least one of the --source or --input arguments must be present, missing one is read from stdin.")
                exit(0)
            else:
                stderr_print("ERR: Invalid arguments", 10)
        if self.input_file == "" and self.source_file == "":
            stderr_print("ERR: Missing arguments", 10)

    def check_xml(self):
        order = 0
        self.root = self.tree.getroot()
        try:
            self.root[:] = sorted(self.root, key=lambda inst: (inst.tag, int(inst.attrib['order'])))
        except Exception:
            stderr_print("ERR: Invalid XML, sorting of instructions failed", 32)
        if self.root.tag != "program":
            stderr_print("ERR: Invalid XML, root tag is not program", 32)
        language_here = False
        for key in self.root.attrib.keys():
            if key != "language" and key != "name" and key != "description":
                stderr_print("ERR: Invalid XML, root attributes are not valid", 32)
            if key == "language":
                language_here = True
        if language_here is False:
            stderr_print("ERR: Invalid XML, root attributes are not valid", 32)
        if self.root.attrib["language"].lower() != "ippcode23":
            stderr_print("ERR: Invalid XML, language is not IPPcode23", 32)
        for child in self.root:
            child[:] = sorted(child, key=lambda argument: argument.tag)
            if child.tag != "instruction":
                stderr_print("ERR: Invalid XML, child tag is not instruction", 32)
            opcode_here = False
            order_here = False
            for key in child.attrib.keys():
                if key != "opcode" and key != "order":
                    stderr_print("ERR: Invalid XML, attributes of instruction are not valid", 32)
                if key == "opcode":
                    opcode_here = True
                if key == "order":
                    order_here = True
            if opcode_here is False or order_here is False:
                stderr_print("ERR: Invalid XML, attributes of instruction are not valid", 32)
            if child.attrib["order"] == "":
                stderr_print("ERR: Invalid XML, order is empty", 32)
            if int(child.attrib["order"]) > order:
                order = int(child.attrib["order"])
            else:
                stderr_print("ERR: Invalid XML, instructions are not in ascending order", 32)
            if child.attrib["opcode"].upper() not in self.INSTRUCTIONS:
                stderr_print("ERR: Invalid XML, opcode is not valid", 32)
            for arg in child:
                if arg.tag != "arg1" and arg.tag != "arg2" and arg.tag != "arg3":
                    stderr_print("ERR: Invalid XML, arg tag is not valid", 32)
                if arg.attrib["type"] == "":
                    stderr_print("ERR: Invalid XML, arg type is empty", 31)
                if arg.attrib["type"] not in ["var", "label", "type", "int", "string", "bool", "nil"]:
                    stderr_print("ERR: Invalid XML, arg type is not valid", 32)
                if arg.attrib["type"] == "var":
                    if not re.match(r"^(GF|LF|TF)@[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$", arg.text):
                        stderr_print("ERR: Invalid XML, var is not valid", 32)
                if arg.attrib["type"] == "label":
                    if not re.match(r'^[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$', arg.text):
                        stderr_print("ERR: Invalid XML, label is not valid", 32)
                if arg.attrib["type"] == "type":
                    if arg.text not in ["int", "string", "bool"]:
                        stderr_print("ERR: Invalid XML, type is not valid", 32)
                if arg.attrib["type"] == "int":
                    if not re.match(r'^[-+]?[0-9]+$', arg.text):
                        stderr_print("ERR: Invalid XML, int is not valid", 32)
                if arg.attrib["type"] == "string":
                    if not re.match(r'^[^\s#\\\\]|(\\[0-9]{3})*$', "" if arg.text is None else arg.text):
                        stderr_print("ERR: Invalid XML, string is not valid", 32)
                if arg.attrib["type"] == "bool":
                    if arg.text != "true" or arg.text != "false":
                        stderr_print("ERR: Invalid XML, bool is not valid", 32)
                if arg.attrib["type"] == "nil":
                    if arg.text != "nil":
                        stderr_print("ERR: Invalid XML, nil is not valid", 32)

    def check_instruction_args(self, instruction):
        if instruction.opcode in ["MOVE", "TYPE"]:
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["CREATEFRAME", "PUSHFRAME", "POPFRAME", "RETURN", "BREAK"]:
            if len(instruction.args) != 0:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
        elif instruction.opcode in ["DEFVAR", "POPS"]:
            if len(instruction.args) != 1:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["CALL", "LABEL", "JUMP"]:
            if len(instruction.args) != 1:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "label":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["PUSHS", "WRITE", "DPRINT"]:
            if len(instruction.args) != 1:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "EXIT":
            if len(instruction.args) != 1:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "int":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["ADD", "SUB", "MUL", "IDIV"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["LT", "GT", "EQ"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "int", "string", "bool"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "int", "string", "bool"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["AND", "OR"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "bool"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "bool"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "NOT":
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "bool"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "INT2CHAR":
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["STRI2INT", "GETCHAR"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "STRLEN":
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "READ":
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ != "type":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "SETCHAR":
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["JUMPIFEQ", "JUMPIFNEQ"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "label":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "CONCAT":
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[1].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)

    def parse_xml(self):
        for child in self.root:
            instruction = Instruction(child.attrib["opcode"].upper(), int(child.attrib["order"]))
            for arg in child:
                instruction.add_arg(Argument(arg.attrib["type"], arg.text))
                if int(arg.tag[3:]) > len(instruction.get_args()):
                    stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            self.check_instruction_args(instruction)
            self.instruction_list.append(instruction)

    def print_instructions(self): # for debugging TODO: remove
        for instruction in self.instruction_list:
            print(instruction.order, instruction.opcode)
            for arg in instruction.args:
                print("\t" + arg.typ, arg.data)


if __name__ == "__main__":
    interpret = Interpret()
    interpret.do_magic()
    # interpret.print_instructions()
    exit(0)
