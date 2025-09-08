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


class IntegerDivision(AbstractDetector):

    ARGUMENT = "int-div"
    HELP = "oscv-6.2.2"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "--"
    WIKI_TITLE = "--"
    WIKI_DESCRIPTION = "--"
    WIKI_EXPLOIT_SCENARIO = "--"
    WIKI_RECOMMENDATION = "--"

    division = " / "
    safeMath = ["mul", "trymul", "safemul", "wmul", "rmul", "mul_", "multiply", "mulchecked", "safemultiply"]

    @staticmethod
    def is_mul_depend(ret_val, function):
        for node in function.nodes:
            for ir in node.irs:
                if isinstance(ir, Binary):
                    if ir.type in [BinaryType.MULTIPLICATION, BinaryType.POWER]:
                        if is_dependent(ret_val, ir.lvalue, function):
                            return True        
        return False

    @staticmethod
    def dependent_return_vals(numenator, _ir, context):
        ret_vals = []
        for ir in _ir.node.irs:
            if isinstance(ir, (LibraryCall, InternalCall)):
                if not isinstance(ir.lvalue, TupleVariable):
                    if is_dependent(numenator, ir.lvalue, context):
                        ret_vals.extend(ir.function.return_values)
            if isinstance(ir, Unpack):
                if is_dependent(numenator, ir.lvalue, context):
                    ret_vals.append(_ir.function.return_values[ir.index])
        
        return ret_vals
    
    @staticmethod
    def is_mul_in_irs(numenator, _irs, context):
        for ir in _irs:
            if isinstance(ir, Binary):
                if ir.type in [BinaryType.MULTIPLICATION, BinaryType.POWER]:
                    if is_dependent(numenator, ir.lvalue, context):
                        return True
            if isinstance(ir, (LibraryCall, InternalCall)):
                if isinstance(ir.function, Function):
                    ret_vals = IntegerDivision.dependent_return_vals(numenator, ir, context)
                    if len(ret_vals) > 0 and str(ir.function_name).lower() in IntegerDivision.safeMath:
                        return True
                    for rv in ret_vals:
                        if IntegerDivision.is_mul_depend(rv, ir.function):
                            return True
                    
        return False

    @staticmethod
    def get_irs(nodes, irs):
        _irs = []
        for node in nodes:
            for ir in node.irs:
                _irs.append(ir)
        for ir in irs:
            _irs.append(ir)
        return _irs

    def _detect(self) -> List[Output]:
        """"""
        results: List[Output] = []
        omit = ["slitherConstructorConstantVariables"]

        for contract in self.compilation_unit.contracts:
            if contract.is_library:
                continue

            for function in contract.functions:
                if function.contract_declarer != contract:
                    continue
                if function.name in omit:
                    continue

                flagged_nodes = []
                nodes = []
                for node in function.nodes:
                    nodes.append(node)
                    if node.contains_require_or_assert():
                        continue
                    if not IntegerDivision.division in str(node):
                        continue
                    
                    irs = []
                    for ir in node.irs:
                        irs.append(ir)
                        if isinstance(ir, Binary):
                            if ir.type in [BinaryType.MULTIPLICATION, BinaryType.POWER]:
                                break
                            if ir.type == BinaryType.DIVISION:
                                numenator = ir.variable_left
                                if is_dependent(numenator, SolidityVariable("now"), node):
                                    continue
                                if is_dependent(numenator, SolidityVariableComposed("block.timestamp"), node):
                                    continue
                                if not IntegerDivision.is_mul_in_irs(numenator, IntegerDivision.get_irs(nodes, irs), ir.node.function):
                                    flagged_nodes.append(node)
                                    break

                if flagged_nodes:
                    info: DETECTOR_INFO = [function, " possible precision loss due to integer division:- \n"]
                    for node in flagged_nodes:
                        info += ["\t- ", node, "\n"]

                    res = self.generate_result(info)
                    results.append(res)

        return results
