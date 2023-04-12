import re
import sys
import xml.etree.ElementTree as ET


INSTRUCTIONS = ("MOVE", "CREATEFRAME", "PUSHFRAME", "POPFRAME",
                "DEFVAR", "CALL", "RETURN", "PUSHS",
                "POPS", "ADD", "SUB", "MUL",
                "IDIV", "LT", "GT", "EQ",
                "AND", "OR", "NOT", "INT2CHAR",
                "STRI2INT", "READ", "WRITE", "CONCAT",
                "STRLEN", "GETCHAR", "SETCHAR", "TYPE",
                "LABEL", "JUMP", "JUMPIFEQ", "JUMPIFNEQ",
                "EXIT", "DPRINT", "BREAK")


def stderr_print(msg):
    sys.stderr.write(msg+"\n")


def arg_parse():
    input_file = ""
    source_file = ""
    for arg in sys.argv[1:]:
        if re.match(r'--input=.*', arg):
            input_file = arg.split('=')[1]
        elif re.match(r'--source=.*', arg):
            source_file = arg.split('=')[1]
        elif arg == "--help":
            print("\nUsage: python interpret_bad.py [--help] [--source=source_file / --input=input_file]")
            print("--source=source_file - path to XML source file")
            print("--input=input_file - path to file with user inputs (can be empty)")
            print("--help - print this help")
            print("At least one of the --source or --input arguments must be present, missing one is read from stdin.")
            exit(0)
        else:
            stderr_print("ERR: Invalid arguments")
            exit(10)
    if input_file == "" and source_file == "":
        stderr_print("ERR: Missing arguments")
        exit(10)

    return input_file, source_file


def check_xml(tree):
    order = 0
    root = tree.getroot()
    try:
        root[:] = sorted(root, key=lambda inst: (inst.tag, int(inst.attrib['order'])))
        if root.tag != "program":
            stderr_print("ERR: Invalid XML, root tag is not program")
            exit(31)
        if root.attrib["language"].lower() != "ippcode23":
            stderr_print("ERR: Invalid XML, language is not IPPcode23")
            exit(32)
        for child in root:
            if child.tag != "instruction":
                stderr_print("ERR: Invalid XML, child tag is not instruction")
                exit(32)
            if child.attrib["order"] == "":
                stderr_print("ERR: Invalid XML, order is empty")
                exit(31)
            if int(child.attrib["order"]) > order:
                order = int(child.attrib["order"])
            else:
                stderr_print("ERR: Invalid XML, instructions are not in ascending order")
                exit(32)
            if child.attrib["opcode"] == "":
                stderr_print("ERR: Invalid XML, opcode is empty")
                exit(31)
            if child.attrib["opcode"].upper() not in INSTRUCTIONS:
                stderr_print("ERR: Invalid XML, opcode is not valid")
                exit(32)
            for arg in child:
                if arg.tag != "arg1" and arg.tag != "arg2" and arg.tag != "arg3":
                    stderr_print("ERR: Invalid XML, arg tag is not valid")
                    exit(32)
                if arg.attrib["type"] == "":
                    stderr_print("ERR: Invalid XML, arg type is empty")
                    exit(31)
                if arg.attrib["type"] not in ["var", "label", "type", "int", "string", "bool", "nil"]:
                    stderr_print("ERR: Invalid XML, arg type is not valid")
                    exit(32)
                if arg.attrib["type"] == "var":
                    if not re.match(r"^(GF|LF|TF)@[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$", arg.text):
                        stderr_print("ERR: Invalid XML, var is not valid")
                        exit(32)
                if arg.attrib["type"] == "label":
                    if not re.match(r'^[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$', arg.text):
                        stderr_print("ERR: Invalid XML, label is not valid")
                        exit(32)
                if arg.attrib["type"] == "type":
                    if arg.text not in ["int", "string", "bool"]:
                        stderr_print("ERR: Invalid XML, type is not valid")
                        exit(32)
                if arg.attrib["type"] == "int":
                    if not re.match(r'^[-+]?[0-9]+$', arg.text):
                        stderr_print("ERR: Invalid XML, int is not valid")
                        exit(32)
                if arg.attrib["type"] == "string":
                    if not re.match(r'^[^\s#\\\\]|(\\[0-9]{3})*$', "" if arg.text is None else arg.text):
                        stderr_print("ERR: Invalid XML, string is not valid")
                        exit(32)
                if arg.attrib["type"] == "bool":
                    if arg.text != "true" or arg.text != "false":
                        stderr_print("ERR: Invalid XML, bool is not valid")
                        exit(32)
                if arg.attrib["type"] == "nil":
                    if arg.text != "nil":
                        stderr_print("ERR: Invalid XML, nil is not valid")
                        exit(32)
    except:
        stderr_print("ERR: Invalid XML")
        exit(31)
    return root


def main():

    """Program entry point."""

    input_file, source_file = arg_parse()
    if source_file == "":
        tree = ET.parse(sys.stdin, ET.XMLParser(encoding="utf-8"))
    else:
        try:
            tree = ET.parse(source_file, ET.XMLParser(encoding="utf-8"))
        except:
            stderr_print("ERR: XML file has invalid format")
            exit(31)
    if input_file == "":
        input_file = sys.stdin
    else:
        try:
            input_file = open(input_file, "r")
        except FileNotFoundError:
            stderr_print("ERR: Nonexistent input file")
            exit(31)

    root = check_xml(tree)
    return 0


if __name__ == "__main__":
    main()
