#!/bin/sh

# This script generates a list of all parameters/variables, and their corresponding
# function name, that contains the DW_OP_GNU_parameter_ref operation in their DWARF
# location expression.

dwgrep ${1} -f /dev/stdin <<"EOF"
let S := entry ?TAG_subprogram;
let P := S child ?((?TAG_formal_parameter, ?TAG_variable) (@AT_location elem label == DW_OP_GNU_parameter_ref));
drop
"function: %( S @AT_name %), variable: %( P @AT_name %)"
