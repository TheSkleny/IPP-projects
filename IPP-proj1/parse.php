<?php
/**
 * IPP project, task 1: parse.php
 * Author: David Sklenář (xsklen14)
 * Date: 2023-02-15
*/
ini_set('display_errors', 'stderr');


// error codes
define("OK", 0);
define("PARAM_ERR", 10);
define("INPUT_ERR", 11);
define("OUTPUT_ERR", 12);
define("INTERNAL_ERR", 99);

define("MISSING_HEADER", 21);
define("UNKNOWN_CODE", 22);
define("GENERAL_ERROR", 23);

/**
 * @brief Validates command line parameters
 * 
 * @param $argc - number of parameters
 * @param $argv - array of parameters
 * exits with error code if parameters are invalid
 */
function validate_params($argc, $argv) {
    if ($argc > 2) {
        fwrite(STDERR, "Wrong number of parameters, run 'parse.php --help' for help\n");
    }
    if ($argc == 2) {
        if ($argv[1] == "--help") {
            echo("Script takes source code from standard input and writes XML representation to standard output.\n");
            echo("param --help: prints this help message\n");
            echo("Usage: php8.1 parse.php [--help] < source_file > output_file\n");
            exit(OK);
        }
        else {
            fwrite(STDERR, "Wrong parameter, run 'parse.php --help' for help\n");
            exit(PARAM_ERR);
        }
    }
}

/**
 * @brief Checks if the variable of IPPcode23 is in valid format
 * 
 * @param $var - variable to be checked
 * @return true if variable is valid, exits program with error code otherwise
 */
function validate_var($var) {
    if (preg_match('/^(GF|LF|TF)@[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$/', $var)) {
        return true;
    }
    fwrite(STDERR, "Invalid variable\n");
    exit(GENERAL_ERROR);
}

/**
 * @brief Checks if the label of IPPcode23 is in valid format
 * 
 * @param $label - label to be checked
 * @return true if label is valid, exits program with error code otherwise
 */
function validate_label($label) {
    if (preg_match('/^[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$/', $label)) {
        return true;
    }
    fwrite(STDERR, "Invalid label\n");
    exit(GENERAL_ERROR);
}


/**
 * @brief Checks if the symbol (variable or constant) of IPPcode23 is in valid format
 * 
 * @param $sumb - symbol to be checked
 * @return true if symbol is valid, exits program with error code otherwise
 */
function validate_symb($symb) {
    // constant
    if (preg_match('/^nil@nil$/', $symb) || 
        preg_match('/^bool@(true|false)$/', $symb) || 
        preg_match('/^int@[-+]?[0-9]+$/', $symb) || 
        preg_match('/^string@([^\s#\\\\]|(\\\[0-9]{3}))*$/', $symb)) {
        return true;
    }
    // variable
    if (preg_match('/^(GF|LF|TF)@[a-zA-Z_$&%*!?-][a-zA-Z0-9_$&%*!?-]*$/', $symb)) {
        return true;
    }
    fwrite(STDERR, "Invalid symbol\n");
    exit(GENERAL_ERROR);
}

/**
 * @brief Checks if the type of IPPcode23 is in valid format
 * 
 * @param $type - type to be checked
 * @return true if type is valid, exits program with error code otherwise
 */
function validate_type($type) {
    if (preg_match('/^(int|string|bool)$/', $type)) {
        return true;
    }
    fwrite(STDERR, "Invalid type\n");
    exit(GENERAL_ERROR);
}

/**
 * @brief Checks what type of symbol is currently being processed
 * 
 * @param $symb - symbol to be checked
 * @return symbol type if it checks, exits program with error code otherwise
 */
function validate_symb_type($symb) {
    $symb_type = strtolower(substr($symb, 0, strpos($symb, "@")));
    switch($symb_type) {
        case "int":
            return "int";
        case "string":
            return "string";
        case "bool":
            return "bool";
        case "nil":
            return "nil";
        case "gf":
        case "lf":
        case "tf":
            return "var";
        default:
            fwrite(STDERR, "Invalid symbol type\n");
            exit(GENERAL_ERROR);
    }
}

/**
 * @brief Replaces all special characters in string with their XML representation
 * 
 * @param $string - string with problematic characters
 * @return string with replaced characters
 */
function replace_special_chars($string) {
    $string = str_replace("&", "&amp;", $string);
    $string = str_replace("<", "&lt;", $string);
    $string = str_replace(">", "&gt;", $string);
    $string = str_replace("\"", "&quot;", $string);
    $string = str_replace("'", "&apos;", $string);
    return $string;
}


/**
 * @brief Generates instruction start
 * 
 * @param $inst_order - order of instruction in program
 * @param $opcode - instruction operation code
 * @return string with generated instruction start
 */
function generate_instr_start($inst_order, $opcode) {
    return "\t<instruction order=\"$inst_order\" opcode=\"".strtoupper($opcode)."\">\n";
}

/**
 * @brief Generates instruction end
 * 
 * @return string with generated instruction end
 */
function generate_instr_end() {
    return "\t</instruction>\n";
}

/**
 * @brief Generates variable argument
 * 
 * @param $arg_order - order of argument in instruction
 * @param $var - variable to be generated
 * @return string with generated variable argument
 */
function generate_var($arg_order, $var) {
    return "\t\t<arg$arg_order type=\"var\">".replace_special_chars($var)."</arg$arg_order>\n";
}

/**
 * @brief Generates symbol argument
 * 
 * @param $arg_order - order of argument in instruction
 * @param $symb - symbol to be generated
 * @return string with generated symbol argument
 */
function generate_symbol($arg_order, $symb) {
    $symb_type = validate_symb_type($symb);
    if ($symb_type === "var") {
        return "\t\t<arg$arg_order type=\"var\">".replace_special_chars($symb)."</arg$arg_order>\n";
    }
    else {
        return "\t\t<arg$arg_order type=\"$symb_type\">".replace_special_chars(substr($symb, strpos($symb, "@") + 1))."</arg$arg_order>\n";
    }
}

/**
 * @brief Generates type argument
 * 
 * @param $arg_order - order of argument in instruction
 * @param $type - type to be generated
 * @return string with generated type argument
 */
function generate_type($arg_order, $type) {
    return "\t\t<arg$arg_order type=\"type\">$type</arg$arg_order>\n";
}

/**
 * @brief Generates label argument
 * 
 * @param $arg_order - order of argument in instruction
 * @param $label - label to be generated
 * @return string with generated label argument
 */
function generate_label($arg_order, $label) {
    return "\t\t<arg$arg_order type=\"label\">$label</arg$arg_order>\n";
}


/**
 * @brief main program function
 * 
 * exits with 0 if program was successful, or with error code otherwise
 */
function main(){
    $input = fopen( 'php://stdin', 'r' );
    $head = false;
    $inst_order = 1;
    $output = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    
    while (($line = fgets($input)) !== false) {
        
        // skip comments
        $line = explode("#", $line)[0];

        // skip empty lines
        if (trim($line) === '') {
            continue;
        }

        // check head
        if ($head === false && trim($line) !== '') {
            if (preg_match('/^\.IPPcode23$/', trim(explode("#", $line)[0]))) {
                $head = true;
                $output .= "<program language=\"IPPcode23\">\n";
            }
            else {
                fwrite(STDERR, "Missing header\n");
                exit(MISSING_HEADER);
            }
            continue;
        }
        
        // split line
        $splitted_line = preg_split('/\s+/', trim($line));
        
        // uppercase operation code
        $splitted_line[0] = strtoupper($splitted_line[0]);
        
        switch($splitted_line[0]){

            // <var> <symb>
            case "MOVE":
            case "INT2CHAR":
            case "NOT":
            case "STRLEN":
            case "TYPE":
                if (count($splitted_line) !== 3) {
                    fwrite(STDERR, "Wrong number of arguments\n");
                    exit(GENERAL_ERROR);
                } elseif (validate_var($splitted_line[1]) && validate_symb($splitted_line[2])) {
                    $output .= generate_instr_start($inst_order, $splitted_line[0]);
                    $output .= generate_var(1, $splitted_line[1]);
                    $output .= generate_symbol(2, $splitted_line[2]);
                    $output .= generate_instr_end();
                }
                break;

            // <var> <type>
            case "READ":
                if (count($splitted_line) !== 3) {
                    fwrite(STDERR, "Wrong number of arguments\n");
                    exit(GENERAL_ERROR);
                } elseif (validate_var($splitted_line[1]) && validate_type($splitted_line[2])) {
                    $output .= generate_instr_start($inst_order, $splitted_line[0]);
                    $output .= generate_var(1, $splitted_line[1]);
                    $output .= generate_type(2, $splitted_line[2]);
                    $output .= generate_instr_end();
                }
                break;

            // <var>
            case "DEFVAR":
            case "POPS":
                if (count($splitted_line) !== 2) {
                    fwrite(STDERR, "Wrong number of arguments\n");
                    exit(GENERAL_ERROR);
                } elseif (validate_var($splitted_line[1])) {
                    $output .= generate_instr_start($inst_order, $splitted_line[0]);
                    $output .= generate_var(1, $splitted_line[1]);
                    $output .= generate_instr_end();
                }
                break;

            // <symb>
            case "PUSHS":
            case "WRITE":
            case "EXIT":
            case "DPRINT":
                if (count($splitted_line) !== 2) {
                    fwrite(STDERR, "Wrong number of arguments\n");
                    exit(GENERAL_ERROR);
                } elseif (validate_symb($splitted_line[1])) {
                    $output .= generate_instr_start($inst_order, $splitted_line[0]);
                    $output .= generate_symbol(1, $splitted_line[1]);
                    $output .= generate_instr_end();
                }
                break;

            // <label>
            case "LABEL":
            case "JUMP":
            case "CALL":
                if (count($splitted_line) !== 2) {
                    fwrite(STDERR, "Wrong number of arguments\n");
                    exit(GENERAL_ERROR);
                } elseif (validate_label($splitted_line[1])) {
                    $output .= generate_instr_start($inst_order, $splitted_line[0]);
                    $output .= generate_label(1, $splitted_line[1]);
                    $output .= generate_instr_end();
                }
                break;
            
            // nothing
            case "CREATEFRAME":
            case "PUSHFRAME":
            case "POPFRAME":
            case "RETURN":
            case "BREAK":
                if (count($splitted_line) !== 1) {
                    fwrite(STDERR, "Wrong number of arguments\n");
                    exit(GENERAL_ERROR);
                } else {
                    $output .= generate_instr_start($inst_order, $splitted_line[0]);
                    $output .= generate_instr_end();
                }
                break;

            // <var> <symb1> <symb2>
            case "ADD":
            case "SUB":
            case "MUL":
            case "IDIV":
            case "LT":
            case "GT":
            case "EQ":
            case "AND":
            case "OR":
            case "STRI2INT":
            case "CONCAT":
            case "GETCHAR":
            case "SETCHAR":
                if (count($splitted_line) !== 4) {
                    fwrite(STDERR, "Wrong number of arguments\n");
                    exit(GENERAL_ERROR);
                } elseif (validate_var($splitted_line[1]) && validate_symb($splitted_line[2]) && validate_symb($splitted_line[3])) {
                    $output .= generate_instr_start($inst_order, $splitted_line[0]);
                    $output .= generate_var(1, $splitted_line[1]);
                    $output .= generate_symbol(2, $splitted_line[2]);
                    $output .= generate_symbol(3, $splitted_line[3]);
                    $output .= generate_instr_end();
                }
                break;

            // <label> <symb1> <symb2>
            case "JUMPIFEQ":
            case "JUMPIFNEQ":
                if (count($splitted_line) !== 4) {
                    fwrite(STDERR, "Wrong number of arguments\n");
                    exit(GENERAL_ERROR);
                } elseif (validate_label($splitted_line[1]) && validate_symb($splitted_line[2]) && validate_symb($splitted_line[3])) {
                    $output .= generate_instr_start($inst_order, $splitted_line[0]);
                    $output .= generate_label(1, $splitted_line[1]);
                    $output .= generate_symbol(2, $splitted_line[2]);
                    $output .= generate_symbol(3, $splitted_line[3]);
                    $output .= generate_instr_end();
                }
                break;
            
            // unknown operation code
            default:
                fwrite(STDERR, "Unknown code\n");
                exit(UNKNOWN_CODE);
        }
        $inst_order++;
    }
    fclose($input);
    $output .= "</program>\n";
    echo($output);
    exit(OK);
}

validate_params($argc, $argv);
main();

?>