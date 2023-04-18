import re
import sys
import xml.etree.ElementTree as ET
import fileinput


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

    def convert_data(self):
        if self.typ == "int":
            self.data = int(self.data)
        elif self.typ == "bool":
            self.data = True if self.data == "true" else False
        elif self.typ == "string":
            self.data = str(self.data)
        elif self.typ == "nil":
            self.data = "nil"
        elif self.typ == "type":
            self.data = self.data
        elif self.typ == "var":
            self.data = self.data
        else:
            stderr_print("ERR: Invalid argument type", 32)


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

    def set_value(self, value):
        self.value = value

    def set_type(self, typ):
        self.type = typ

    def set_name(self, name):
        self.name = name


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
    def __init__(self, instructions, input_file):
        self.instructions = instructions
        self.instruction_index = 0
        self.instruction = None
        self._GF_frame = Frame()
        self._LF_frame = None  # it is defined only when it is needed
        self._TF_frame = None  # it is defined only when it is created or poped
        self._labels = {}
        self._frames_stack = Stack()
        self._data_stack = Stack()
        self._input_file = input_file

    @staticmethod
    def _translate_string(string):
        return re.sub(r"\\([0-9]{3})", lambda x: chr(int(x.group(1))), string)
        
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

    def _arithmetic(self, instruction, operation):
        var_save = self._get_var(instruction.get_arg(0).get_data())
        if instruction.get_arg(1).get_type() == "var":
            var1 = self._get_var(instruction.get_arg(1).get_data())
        else:
            var1 = Variable("temp", instruction.get_arg(1).get_type(), instruction.get_arg(1).get_data())
        if instruction.get_arg(2).get_type() == "var":
            var2 = self._get_var(instruction.get_arg(2).get_data())
        else:
            var2 = Variable("temp2", instruction.get_arg(2).get_type(), instruction.get_arg(2).get_data())
        if var1.get_type() == "int" and var2.get_type() == "int":
            match operation:
                case "add":
                    var_save.set_value(int(var1.get_value()) + int(var2.get_value()))
                case "sub":
                    var_save.set_value(int(var1.get_value()) - int(var2.get_value()))
                case "mul":
                    var_save.set_value(int(var1.get_value()) * int(var2.get_value()))
                case "idiv":
                    if int(var2.get_value()) == 0:
                        stderr_print("ERR: Division by zero", 57)
                    var_save.set_value(int(var1.get_value()) // int(var2.get_value()))
            var_save.set_type("int")
        else:
            stderr_print("ERR: Arithmetic operation with non-integers", 53)

    def _and_or(self, instruction, operation):
        var_save = self._get_var(instruction.get_arg(0).get_data())
        if instruction.get_arg(1).get_type() == "var":
            var1 = self._get_var(instruction.get_arg(1).get_data())
        else:
            var1 = Variable("temp", instruction.get_arg(1).get_type(), instruction.get_arg(1).get_data())
        if instruction.get_arg(2).get_type() == "var":
            var2 = self._get_var(instruction.get_arg(2).get_data())
        else:
            var2 = Variable("temp", instruction.get_arg(2).get_type(), instruction.get_arg(2).get_data())
        if var1.get_type() == "bool" and var2.get_type() == "bool":
            var_save.set_type("bool")
            if operation == "and":
                var_save.set_value(True if var1.get_value() is True and var2.get_value() is True else False)
            elif operation == "or":
                var_save.set_value(True if var1.get_value() is True or var2.get_value() is True else False)
            else: # should not happen
                stderr_print("ERR: Invalid operation for AND/OR", 32)
        else:
            stderr_print("ERR: Invalid types for AND/OR", 53)

    def _compare(self, instruction, operation):
        var_save = self._get_var(instruction.get_arg(0).get_data())
        if instruction.get_arg(1).get_type() == "var":
            var1 = self._get_var(instruction.get_arg(1).get_data())
        else:
            var1 = Variable("temp", instruction.get_arg(1).get_type(), instruction.get_arg(1).get_data())
        if instruction.get_arg(2).get_type() == "var":
            var2 = self._get_var(instruction.get_arg(2).get_data())
        else:
            var2 = Variable("temp", instruction.get_arg(2).get_type(), instruction.get_arg(2).get_data())
        if var1.get_type() == var2.get_type():
            var_save.set_type("bool")
            if operation == "eq":
                var_save.set_value(True if var1.get_value() == var2.get_value() else False)
            elif operation == "lt":
                if var1.get_type() == "nil" or var2.get_type() == "nil":
                    stderr_print("ERR: Invalid types for compare", 53)
                var_save.set_value(True if var1.get_value() < var2.get_value() else False)
            elif operation == "gt":
                if var1.get_type() == "nil" or var2.get_type() == "nil":
                    stderr_print("ERR: Invalid types for compare", 53)
                var_save.set_value(True if var1.get_value() > var2.get_value() else False)
            else: # should not happen
                stderr_print("ERR: Invalid operation for compare", 32)
        elif var1.get_type() == "nil" or var2.get_type() == "nil":
            var_save.set_type("bool")
            if operation == "eq":
                var_save.set_value(True if var1.get_type() == var2.get_type() else False)
            else:
                stderr_print("ERR: Invalid types for compare", 53)
        else:
            stderr_print("ERR: Invalid types for compare", 53)
    
    def execute(self):
        for instr in self.instructions:
            match instr.opcode:
                case "MOVE":
                    self.move(instr)
                case "CREATEFRAME":
                    self.create_frame(instr)
                case "PUSHFRAME":
                    self.push_frame(instr)
                case "POPFRAME":
                    self.pop_frame(instr)
                case "DEFVAR":
                    self.def_var(instr)
                case "CALL":
                    self.call(instr)
                case "RETURN":
                    self.return_(instr)
                case "PUSHS":
                    self.pushs(instr)
                case "POPS":
                    self.pops(instr)
                case "ADD":
                    self.add(instr)
                case "SUB":
                    self.sub(instr)
                case "MUL":
                    self.mul(instr)
                case "IDIV":
                    self.idiv(instr)
                case "LT":
                    self.lt(instr)
                case "GT":
                    self.gt(instr)
                case "EQ":
                    self.eq(instr)
                case "AND":
                    self.and_(instr)
                case "OR":
                    self.or_(instr)
                case "NOT":
                    self.not_(instr)
                case "INT2CHAR":
                    self.int2char(instr)
                case "STRI2INT":
                    self.stri2int(instr)
                case "READ":
                    self.read(instr)
                case "WRITE":
                    self.write(instr)
                case "CONCAT":
                    self.concat(instr)
                case "STRLEN":
                    self.strlen(instr)
                case "GETCHAR":
                    self.getchar(instr)
                case "SETCHAR":
                    self.setchar(instr)
                case "TYPE":
                    self.type_(instr)
                case "LABEL":
                    self.label(instr)
                case "JUMP":
                    self.jump(instr)
                case "JUMPIFEQ":
                    self.jumpifeq(instr)
                case "JUMPIFNEQ":
                    self.jumpifneq(instr)
                case "EXIT":
                    self.exit(instr)
                case "DPRINT":
                    self.dprint(instr)
                case "BREAK":
                    self.break_(instr)
                case _:  # default
                    stderr_print("ERR: Invalid instruction", 32)

    def move(self, instruction):
        var = self._get_var(instruction.get_arg(0).get_data())
        if instruction.get_arg(1).get_type() == "var":
            var.set_value(self._get_var(instruction.get_arg(1).get_data()).get_value())
            var.set_type(self._get_var(instruction.get_arg(1).get_data()).get_type())
        else:
            var.set_value(instruction.get_arg(1).get_data())
            var.set_type(instruction.get_arg(1).get_type())

    def create_frame(self, instruction):
        raise NotImplementedError

    def push_frame(self, instruction):
        raise NotImplementedError

    def pop_frame(self, instruction):
        raise NotImplementedError

    def def_var(self, instruction):
        var = instruction.get_arg(0).get_data()
        if var[0] == "G":
            self._GF_frame.add_variable(Variable(var, None, None))
        elif var[0] == "L":
            try:
                self._LF_frame.add_variable(Variable(var, None, None))
            except AttributeError:
                stderr_print("ERR: Local frame not defined", 55)
        elif var[0] == "T":
            try:
                self._TF_frame.add_variable(Variable(var, None, None))
            except AttributeError:
                stderr_print("ERR: Temporary frame not defined", 55)
        else:
            stderr_print("ERR: Invalid variable name", 32)

    def call(self, instruction):
        raise NotImplementedError

    def return_(self, instruction):
        raise NotImplementedError

    def pushs(self, instruction):
        raise NotImplementedError

    def pops(self, instruction):
        raise NotImplementedError

    def add(self, instruction):
        self._arithmetic(instruction, "add")

    def sub(self, instruction):
        self._arithmetic(instruction, "sub")

    def mul(self, instruction):
        self._arithmetic(instruction, "mul")

    def idiv(self, instruction):
        self._arithmetic(instruction, "idiv")

    def lt(self, instruction):
        self._compare(instruction, "lt")

    def gt(self, instruction):
        self._compare(instruction, "gt")

    def eq(self, instruction):
        self._compare(instruction, "eq")

    def and_(self, instruction):
        self._and_or(instruction, "and")

    def or_(self, instruction):
        self._and_or(instruction, "or")

    def not_(self, instruction):
        var_set = self._get_var(instruction.get_arg(0).get_data())
        if instruction.get_arg(1).get_type() == "var":
            var = self._get_var(instruction.get_arg(1).get_data())
        else:
            var = Variable("tmp", instruction.get_arg(1).get_type(), instruction.get_arg(1).get_data())
        if var.get_type() == "bool":
            var_set.set_value(not var.get_value())
            var_set.set_type("bool")
        else:
            stderr_print("ERR: Invalid type of variable", 53)

    def int2char(self, instruction):
        var_set = self._get_var(instruction.get_arg(0).get_data())
        if instruction.get_arg(1).get_type() == "var":
            var = self._get_var(instruction.get_arg(1).get_data())
        else:
            var = Variable("tmp", instruction.get_arg(1).get_type(), instruction.get_arg(1).get_data())
        if var.get_type() == "int":
            try:
                var_set.set_value(chr(var.get_value()))
                var_set.set_type("string")
            except ValueError:
                stderr_print("ERR: Invalid value of variable", 58)
        else:
            stderr_print("ERR: Invalid type of variable", 53)

    def stri2int(self, instruction):
        var_set = self._get_var(instruction.get_arg(0).get_data())
        if instruction.get_arg(1).get_type() == "var":
            var1 = self._get_var(instruction.get_arg(1).get_data())
        else:
            var1 = Variable("tmp", instruction.get_arg(1).get_type(), instruction.get_arg(1).get_data())
        if instruction.get_arg(2).get_type() == "var":
            var2 = self._get_var(instruction.get_arg(2).get_data())
        else:
            var2 = Variable("tmp", instruction.get_arg(2).get_type(), instruction.get_arg(2).get_data())
        if var1.get_type() == "string" and var2.get_type() == "int":
            try:
                var_set.set_value(ord(var1.get_value()[var2.get_value()]))
                var_set.set_type("int")
            except IndexError:
                stderr_print("ERR: Invalid value of variable", 58)
        else:
            stderr_print("ERR: Invalid type of variable", 53)

    def read(self, instruction):
        var = self._get_var(instruction.get_arg(0).get_data())
        type_ = instruction.get_arg(1).get_data()
        inp = input() if self._input_file == "" else self._input_file.readline()
        if type_ == "int":
            try:
                var.set_value(int(inp.strip()))
                var.set_type("int")
            except ValueError:
                var.set_type("nil")
                var.set_value("nil@nil")
        elif type_ == "bool":
            try:
                if inp.strip() == "":
                    var.set_type("nil")
                    var.set_value("nil@nil")
                else:
                    var.set_value(True if inp.strip() == "true" else False)
                    var.set_type("bool")
            except ValueError:
                var.set_type("nil")
                var.set_value("nil@nil")
        elif type_ == "string":
            try:
                var.set_value(inp.strip())
                var.set_type("string")
            except ValueError:
                var.set_type("nil")
                var.set_value("nil@nil")
        else:
            var.set_type("nil")
            var.set_value("nil@nil")

    def write(self, instruction):
        if instruction.get_arg(0).get_type() == "bool":
            print("true" if instruction.get_arg(0).get_data() is True else "false", end="")
        elif instruction.get_arg(0).get_type() == "nil":
            print("", end="")
        elif instruction.get_arg(0).get_type() == "var":
            var = self._get_var(instruction.get_arg(0).get_data())
            if var.get_type() == "bool":
                print("true" if var.get_value() is True else "false", end="")
            elif var.get_type() == "string":
                print(self._translate_string(var.get_value()), end="")
            elif var.get_type() == "nil":
                print("", end="")
            else:
                print(var.get_value(), end="")
        elif instruction.get_arg(0).get_type() == "string":
            print(self._translate_string(instruction.get_arg(0).get_data()), end="")
        else:
            print(instruction.get_arg(0).get_data(), end="")

    def concat(self, instruction):
        raise NotImplementedError

    def strlen(self, instruction):
        raise NotImplementedError

    def getchar(self, instruction):
        raise NotImplementedError

    def setchar(self, instruction):
        raise NotImplementedError

    def type_(self, instruction):
        var_set = self._get_var(instruction.get_arg(0).get_data())
        if instruction.get_arg(1).get_type() == "var":
            var = self._get_var(instruction.get_arg(1).get_data())
        else:
            var = Variable("tmp", instruction.get_arg(1).get_type(), instruction.get_arg(1).get_data())
        var_set.set_value(var.get_type() if var.get_type() is not None else "")
        var_set.set_type("string")

    def label(self, instruction):
        raise NotImplementedError

    def jump(self, instruction):
        raise NotImplementedError

    def jumpifeq(self, instruction):
        raise NotImplementedError

    def jumpifneq(self, instruction):
        raise NotImplementedError

    def exit(self, instruction):
        var = self._get_var(instruction.get_arg(0).get_data())
        if var.get_type() == "int":
            exit(var.get_value())
        else:
            stderr_print("ERR: Invalid type of variable", 53)

    def dprint(self, instruction):
        if instruction.get_arg(0).get_type() == "var":
            sys.stderr.write(self._get_var(instruction.get_arg(0).get_data()).get_value())
        else:
            sys.stderr.write(instruction.get_arg(0).get_data())

    def break_(self, instruction):
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
        execute = ExecuteProgram(self.instruction_list, self.input_file)
        execute.execute()

    def read_files(self):
        if self.source_file == "":
            self.tree = ET.parse(sys.stdin, ET.XMLParser(encoding="utf-8"))
        else:
            try:
                self.tree = ET.parse(self.source_file, ET.XMLParser(encoding="utf-8"))
            except Exception:
                stderr_print("ERR: XML file has invalid format", 31)
        if self.input_file != "":
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
                if key == "opcode":
                    opcode_here = True
                if key == "order":
                    order_here = True
            if opcode_here is False or order_here is False:
                stderr_print("ERR: Invalid XML, attributes of instruction are not valid", 32)
            if child.attrib["order"] == "":
                stderr_print("ERR: Invalid XML, order is empty", 32)
            try:
                if int(child.attrib["order"]) > order:
                    order = int(child.attrib["order"])
                else:
                    stderr_print("ERR: Invalid XML, instructions are not in ascending order", 32)
            except Exception:
                stderr_print("ERR: Invalid XML, order is not integer", 32)
            if child.attrib["opcode"].upper() not in self.INSTRUCTIONS:
                stderr_print("ERR: Invalid XML, opcode is not valid", 32)
            for arg in child:
                if arg.tag != "arg1" and arg.tag != "arg2" and arg.tag != "arg3":
                    stderr_print("ERR: Invalid XML, arg tag is not valid", 32)
                type_here = False
                for key in arg.attrib.keys():
                    if key == "type":
                        type_here = True
                if type_here is False:
                    stderr_print("ERR: Invalid XML, arg attributes are not valid", 32)
                if arg.attrib["type"] == "":
                    stderr_print("ERR: Invalid XML, arg type is empty", 31)
                if arg.attrib["type"] not in ["var", "label", "type", "int", "string", "bool", "nil"]:
                    stderr_print("ERR: Invalid XML, arg type is not valid", 32)
                if arg.attrib["type"] == "var":
                    if not re.match(r"^(GF|LF|TF)@[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$", str(arg.text).strip()):
                        stderr_print("ERR: Invalid XML, var is not valid", 52)
                if arg.attrib["type"] == "label":
                    if not re.match(r'^[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$', arg.text):
                        stderr_print("ERR: Invalid XML, label is not valid", 32)
                if arg.attrib["type"] == "type":
                    if arg.text not in ["int", "string", "bool"]:
                        stderr_print("ERR: Invalid XML, type is not valid", 32)
                if arg.attrib["type"] == "int":
                    if not re.match(r'^[-+]?[0-9]+$', str(arg.text).strip()):
                        stderr_print("ERR: Invalid XML, int is not valid", 32)
                if arg.attrib["type"] == "string":
                    if not re.match(r'^[^\s#\\\\]|(\\[0-9]{3})*$', "" if arg.text is None else str(arg.text).strip()):
                        stderr_print("ERR: Invalid XML, string is not valid", 32)
                if arg.attrib["type"] == "bool":
                    if str(arg.text).strip() != "true" and str(arg.text).strip() != "false":
                        stderr_print("ERR: Invalid XML, bool is not valid", 32)
                if arg.attrib["type"] == "nil":
                    if arg.text != "nil":
                        stderr_print("ERR: Invalid XML, nil is not valid", 32)

    def check_instruction_args(self, instruction):
        if instruction.opcode in ["MOVE", "TYPE"]:
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode in ["CREATEFRAME", "PUSHFRAME", "POPFRAME", "RETURN", "BREAK"]:
            if len(instruction.args) != 0:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
        elif instruction.opcode in ["DEFVAR", "POPS"]:
            if len(instruction.args) != 1:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode in ["CALL", "LABEL", "JUMP"]:
            if len(instruction.args) != 1:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "label":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode in ["PUSHS", "WRITE", "DPRINT"]:
            if len(instruction.args) != 1:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode == "EXIT":
            if len(instruction.args) != 1:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "int":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode in ["ADD", "SUB", "MUL", "IDIV"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode in ["LT", "GT", "EQ"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[2].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode in ["AND", "OR"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "bool"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
            if instruction.args[2].typ not in ["var", "bool"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "NOT":
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "bool"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 53)
        elif instruction.opcode == "INT2CHAR":
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode in ["STRI2INT", "GETCHAR"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[2].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode == "STRLEN":
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode == "READ":
            if len(instruction.args) != 2:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ != "type":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32) # TODO: check if return codes are valid
        elif instruction.opcode == "SETCHAR":
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "int"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[2].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode in ["JUMPIFEQ", "JUMPIFNEQ"]:
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "label":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[2].typ not in ["var", "int", "string", "bool", "nil"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
        elif instruction.opcode == "CONCAT":
            if len(instruction.args) != 3:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong number of arguments", 32)
            if instruction.args[0].typ != "var":
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[1].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)
            if instruction.args[2].typ not in ["var", "string"]:
                stderr_print(f"ERR: Invalid XML, instruction {instruction.opcode} has wrong argument type", 32)

    def parse_xml(self):
        for child in self.root:
            instruction = Instruction(child.attrib["opcode"].upper(), int(child.attrib["order"]))
            for arg in child:
                argg = Argument(arg.attrib["type"], str(arg.text).strip())
                argg.convert_data()
                instruction.add_arg(argg)
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
