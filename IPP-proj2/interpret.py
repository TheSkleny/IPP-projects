import re
import sys
import xml.etree.ElementTree as ET


class Instruction:
    def __init__(self, opcode, order):
        self.opcode = opcode
        self.order = order
        self.args = []

    def add_arg(self, arg):
        self.args.append(arg)


class Argument:
    def __init__(self, typ, data):
        self.typ = typ
        self.data = data


class Variable:
    def __init__(self, name, typ, value):
        self.name = name # contains also frame
        self.type = typ
        self.value = value


class Frame:
    pass


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

    @staticmethod
    def stderr_print(message):
        sys.stderr.write(message + "\n")

    def do_magic(self):
        self.arg_parse()
        self.read_files()
        self.check_xml()
        self.parse_xml()

    def read_files(self):
        if self.source_file == "":
            self.tree = ET.parse(sys.stdin, ET.XMLParser(encoding="utf-8"))
        else:
            try:
                self.tree = ET.parse(self.source_file, ET.XMLParser(encoding="utf-8"))
            except Exception:
                self.stderr_print("ERR: XML file has invalid format")
                exit(31)
        if self.input_file == "":
            self.input_file = sys.stdin
        else:
            try:
                self.input_file = open(self.input_file, "r")
            except FileNotFoundError:
                self.stderr_print("ERR: Nonexistent input file")
                exit(31)

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
                self.stderr_print("ERR: Invalid arguments")
                exit(10)
        if self.input_file == "" and self.source_file == "":
            self.stderr_print("ERR: Missing arguments")
            exit(10)

    def check_xml(self):
        order = 0
        self.root = self.tree.getroot()
        try:
            self.root[:] = sorted(self.root, key=lambda inst: (inst.tag, int(inst.attrib['order'])))
            if self.root.tag != "program":
                self.stderr_print("ERR: Invalid XML, root tag is not program")
                exit(31)
            for key in self.root.attrib.keys():
                if key != "language" and key != "name" and key != "description":
                    self.stderr_print("ERR: Invalid XML, root attributes are not valid")
                    exit(32)
            if self.root.attrib["language"].lower() != "ippcode23":
                self.stderr_print("ERR: Invalid XML, language is not IPPcode23")
                exit(32)
            for child in self.root:
                child[:] = sorted(child, key=lambda argument: argument.tag)
                if child.tag != "instruction":
                    self.stderr_print("ERR: Invalid XML, child tag is not instruction")
                    exit(32)
                for key in child.attrib.keys():
                    if key != "opcode" and key != "order":
                        self.stderr_print("ERR: Invalid XML, attributes of instruction are not valid")
                        exit(32)
                if child.attrib["order"] == "":
                    self.stderr_print("ERR: Invalid XML, order is empty")
                    exit(31)
                if int(child.attrib["order"]) > order:
                    order = int(child.attrib["order"])
                else:
                    self.stderr_print("ERR: Invalid XML, instructions are not in ascending order")
                    exit(32)
                if child.attrib["opcode"] == "":
                    self.stderr_print("ERR: Invalid XML, opcode is empty")
                    exit(31)
                if child.attrib["opcode"].upper() not in self.INSTRUCTIONS:
                    self.stderr_print("ERR: Invalid XML, opcode is not valid")
                    exit(32)
                for arg in child:
                    if arg.tag != "arg1" and arg.tag != "arg2" and arg.tag != "arg3":
                        self.stderr_print("ERR: Invalid XML, arg tag is not valid")
                        exit(32)
                    if arg.attrib["type"] == "":
                        self.stderr_print("ERR: Invalid XML, arg type is empty")
                        exit(31)
                    if arg.attrib["type"] not in ["var", "label", "type", "int", "string", "bool", "nil"]:
                        self.stderr_print("ERR: Invalid XML, arg type is not valid")
                        exit(32)
                    if arg.attrib["type"] == "var":
                        if not re.match(r"^(GF|LF|TF)@[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$", arg.text):
                            self.stderr_print("ERR: Invalid XML, var is not valid")
                            exit(32)
                    if arg.attrib["type"] == "label":
                        if not re.match(r'^[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$', arg.text):
                            self.stderr_print("ERR: Invalid XML, label is not valid")
                            exit(32)
                    if arg.attrib["type"] == "type":
                        if arg.text not in ["int", "string", "bool"]:
                            self.stderr_print("ERR: Invalid XML, type is not valid")
                            exit(32)
                    if arg.attrib["type"] == "int":
                        if not re.match(r'^[-+]?[0-9]+$', arg.text):
                            self.stderr_print("ERR: Invalid XML, int is not valid")
                            exit(32)
                    if arg.attrib["type"] == "string":
                        if not re.match(r'^[^\s#\\\\]|(\\[0-9]{3})*$', "" if arg.text is None else arg.text):
                            self.stderr_print("ERR: Invalid XML, string is not valid")
                            exit(32)
                    if arg.attrib["type"] == "bool":
                        if arg.text != "true" or arg.text != "false":
                            self.stderr_print("ERR: Invalid XML, bool is not valid")
                            exit(32)
                    if arg.attrib["type"] == "nil":
                        if arg.text != "nil":
                            self.stderr_print("ERR: Invalid XML, nil is not valid")
                            exit(32)
        except Exception:
            self.stderr_print("ERR: Invalid XML")
            exit(31)

    def check_instruction_args(self, instruction):
        if instruction.opcode in ["MOVE", "TYPE"]:
            if len(instruction.args) != 2:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "int", "string", "bool", "nil"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode in ["CREATEFRAME", "PUSHFRAME", "POPFRAME", "RETURN", "BREAK"]:
            if len(instruction.args) != 0:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
        elif instruction.opcode not in ["DEFVAR", "POPS"]:
            if len(instruction.args) != 1:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode in ["CALL", "LABEL", "JUMP"]:
            if len(instruction.args) != 1:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "label":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode not in ["PUSHS", "WRITE", "DPRINT"]:
            if len(instruction.args) != 1:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ not in ["var", "int", "string", "bool", "nil"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode == "EXIT":
            if len(instruction.args) != 1:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "int":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode in ["ADD", "SUB", "MUL", "IDIV"]:
            if len(instruction.args) != 3:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "int"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[2].typ not in ["var", "int"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode in ["LT", "GT", "EQ"]:
            if len(instruction.args) != 3:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "int", "string", "bool"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[2].typ not in ["var", "int", "string", "bool"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode in ["AND", "OR"]:
            if len(instruction.args) != 3:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "bool"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[2].typ not in ["var", "bool"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode == "NOT":
            if len(instruction.args) != 2:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "bool"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode == "INT2CHAR":
            if len(instruction.args) != 2:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "int"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode in ["STRI2INT", "GETCHAR"]:
            if len(instruction.args) != 3:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "string"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[2].typ not in ["var", "int"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode == "STRLEN":
            if len(instruction.args) != 2:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "string"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode == "READ":
            if len(instruction.args) != 2:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ != "type":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.type == "SETCHAR":
            if len(instruction.args) != 3:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "int"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[2].typ not in ["var", "string"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode in ["JUMPIFEQ", "JUMPIFNEQ"]:
            if len(instruction.args) != 3:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "label":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "int", "string", "bool", "nil"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[2].typ not in ["var", "int", "string", "bool", "nil"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
        elif instruction.opcode == "CONCAT":
            if len(instruction.args) != 3:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments")
                exit(32)
            if instruction.args[0].typ != "var":
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[1].typ not in ["var", "string"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)
            if instruction.args[2].typ not in ["var", "string"]:
                self.stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type")
                exit(32)

    def parse_xml(self):
        for child in self.root:
            instruction = Instruction(child.attrib["opcode"].upper(), child.attrib["order"])
            for arg in child:
                instruction.add_arg(Argument(arg.attrib["type"], arg.text))
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
    interpret.print_instructions()
