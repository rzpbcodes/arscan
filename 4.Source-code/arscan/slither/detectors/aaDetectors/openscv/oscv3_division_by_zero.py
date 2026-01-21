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

class DivisionByZero(AbstractDetector):

    ARGUMENT = "div-by-zero"
    HELP = "oscv-6.2.1"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "--"
    WIKI_TITLE = "--"
    WIKI_DESCRIPTION = "--"
    WIKI_EXPLOIT_SCENARIO = "--"
    WIKI_RECOMMENDATION = "--"

    accessible = ["public", "external"]

    @staticmethod
    def in_call_div(ir):
        checked_vars = set()
        params = ir.function.parameters
        unchecked_denominators = set()
        for node in ir.function.nodes:
            if node.contains_require_or_assert():
                checked_vars.update(node.variables_read)
            #if node.contains_if(True):
                #checked_vars.update(node.variables_read)
            for ir in node.irs:
                if isinstance(ir, Binary) and ir.type == BinaryType.DIVISION:
                    denominator = ir.variable_right
                    if denominator not in checked_vars:
                        if denominator in params:
                            unchecked_denominators.add(denominator)

        return unchecked_denominators

    @staticmethod
    def params_dependency(unsafe_vars: set, ir_func_params: list, ir_args: list, func_params: list, checked_vars: set):
        issue_params = []
        for param, arg in zip(ir_func_params, ir_args):
            if param in unsafe_vars:
                if arg in func_params and arg not in checked_vars:
                    issue_params.append(arg)
        return issue_params

    def _detect(self) -> List[Output]:
        """"""
        results: List[Output] = []

        for contract in self.compilation_unit.contracts:
            if contract.is_library:
                continue
            for function in contract.functions:
                if function.contract_declarer != contract:
                    continue
                if not function.visibility in DivisionByZero.accessible:
                    continue

                flagged_nodes = set()
                checked_vars = set()
                func_params = set(function.parameters)

                for node in function.nodes:
                    if node.contains_require_or_assert():
                        checked_vars.update(node.variables_read)
                    ##if node.contains_if(True):
                        ##checked_vars.update(node.variables_read)

                    for ir in node.irs:
                        if isinstance(ir, (LibraryCall, InternalCall)):
                            if isinstance(ir.function, Function):
                                denominators = DivisionByZero.in_call_div(ir)
                                issue_params = DivisionByZero.params_dependency(denominators, ir.function.parameters, ir.arguments, func_params, checked_vars)
                                if len(issue_params) > 0:
                                    flagged_nodes.add(node)
                                    break
                        elif isinstance(ir, Binary) and ir.type == BinaryType.DIVISION:
                            denominator = ir.variable_right
                            if isinstance(denominator, Constant):
                                if denominator.value == '0':
                                    flagged_nodes.add(node)
                            elif denominator in func_params and denominator not in checked_vars:
                                flagged_nodes.add(node)
                                break

                if flagged_nodes:
                    info: DETECTOR_INFO = [function, " possible division by zero due to unchecked denominator:- \n"]
                    for node in flagged_nodes:
                        info += ["\t- ", node, "\n"]

                    res = self.generate_result(info)
                    results.append(res)

            
        return results
