import re
import sys
import xml.etree.ElementTree as ET


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
        # self.instruction_list.append(self.read_xml)
        # self.instruction_list.append(self.check_xml)
        # self.instruction_list.append(self.run_xml)
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
            if self.root.attrib["language"].lower() != "ippcode23":
                self.stderr_print("ERR: Invalid XML, language is not IPPcode23")
                exit(32)
            for child in self.root:
                if child.tag != "instruction":
                    self.stderr_print("ERR: Invalid XML, child tag is not instruction")
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

    def parse_xml(self):
        pass

if __name__ == "__main__":
    interpret = Interpret()
    interpret.do_magic()
