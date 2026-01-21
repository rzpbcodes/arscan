from typing import List, Optional
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)

from slither.core.cfg.node import *
from slither.utils.output import *
from slither.slithir.operations import *
from slither.core.declarations import *
from slither.core.expressions import *
from slither.analyses.data_dependency.data_dependency import *
from slither.detectors.aaDetectors.pragma_check import is_safe_pragma

class IntegerUnderflow(AbstractDetector):

    ARGUMENT = "integer-underflow"
    HELP = "oscv-6.1.1"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "--"
    WIKI_TITLE = "--"
    WIKI_DESCRIPTION = "--"
    WIKI_EXPLOIT_SCENARIO = "--"
    WIKI_RECOMMENDATION = "--"

    accessible = ["public", "external"]

    @staticmethod
    def op_vars_in_call(_ir, operation, indexs):
        checked_vars = IntegerUnderflow.checked_vars(_ir.function)
        func_params = set(_ir.function.parameters)
        unsafe_vars = set()
        for node in _ir.function.nodes:
            for ir in node.irs:
                if isinstance(ir, Binary) and ir.type in operation:
                    operands = [ir.get_variable[index] for index in indexs]
                    issue_params = IntegerUnderflow.unsafe_params(operands, node.variables_written, func_params, checked_vars)
                    for param in issue_params:
                        unsafe_vars.add(param)

        return unsafe_vars

    @staticmethod
    def params_dependency(unsafe_vars: set, ir_func_params: list, ir_args: list, func_params: list, checked_vars: set):
        issue_params = []
        for param, arg in zip(ir_func_params, ir_args):
            if param in unsafe_vars:
                if arg in func_params and arg not in checked_vars:
                    issue_params.append(arg)
        return issue_params

    
    @staticmethod 
    def unsafe_params(vars_read:[], vars_written:[], func_params:[], checked_vars:set()):
        issue_params = set()

        for vw in vars_written:
            if vw in checked_vars:
                return set()

        for vr in vars_read:
            vt = vr
            if isinstance(vr, ReferenceVariable):
                vt = vr.points_to_origin
            if vt in func_params and vt not in checked_vars:
                issue_params.add(vt)

        return issue_params
    
    @staticmethod
    def checked_vars(function):
        all_checked_vars = set()
        for node in function.nodes:
            if node.contains_require_or_assert():
                all_checked_vars.update(node.variables_read)
            #if node.contains_if(True):
                #all_checked_vars.update(node.variables_read)

        return all_checked_vars


    def _detect(self) -> List[Output]:
        """"""
        results: List[Output] = []
        ops = [BinaryType.SUBTRACTION]

        for p in self.compilation_unit.pragma_directives:
            if p.is_solidity_version:
                pragma_str = str(p)
                if is_safe_pragma(pragma_str, "0.8.0"):
                    return results

        for contract in self.compilation_unit.contracts:
            if contract.is_library:
                continue
            for function in contract.functions:
                if function.contract_declarer != contract:
                    continue
                if not function.visibility in IntegerUnderflow.accessible:
                    continue

                flagged_nodes = set()
                func_params = set(function.parameters)
                checked_vars = IntegerUnderflow.checked_vars(function)

                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, (LibraryCall, InternalCall)):
                            if isinstance(ir.function, Function):
                                unsafe_vars = IntegerUnderflow.op_vars_in_call(ir, ops, [0,1])
                                issue_params = IntegerUnderflow.params_dependency(unsafe_vars, ir.function.parameters, ir.arguments, func_params, checked_vars)
                                if len(issue_params) > 0:
                                    flagged_nodes.add(node)
                                    break
                        elif isinstance(ir, Binary) and ir.type in ops:
                            issue_params = IntegerUnderflow.unsafe_params(ir.get_variable, node.variables_written, func_params, checked_vars)
                            if len(issue_params) > 0:
                                flagged_nodes.add(node)
                                break

                if flagged_nodes:
                    info: DETECTOR_INFO = [function, " may underflow in subtraction:- \n"]
                    for node in flagged_nodes:
                        info += ["\t- ", node, "\n"]

                    res = self.generate_result(info)
                    results.append(res)

            
        return results
