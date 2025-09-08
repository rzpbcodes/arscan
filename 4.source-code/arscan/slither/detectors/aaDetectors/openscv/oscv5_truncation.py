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
from slither.slithir.operations.type_conversion import TypeConversion
from slither.core.solidity_types.elementary_type import *
import re


class Truncation(AbstractDetector):

    ARGUMENT = "truncation"
    HELP = "oscv-6.3.1"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "--"
    WIKI_TITLE = "--"
    WIKI_DESCRIPTION = "--"
    WIKI_EXPLOIT_SCENARIO = "--"
    WIKI_RECOMMENDATION = "--"

    skip_op = re.compile(r"address\(uint160\(|keccak256\(| >> ")

    issue_type_size = {
        # uint / int: 8, 16, …, 256
        **{
            f"{name}{size}": size
            for name in ("uint", "int")
            for size in range(8, 257, 8)
        },
        # bytes: 1–32 → bits = n * 8
        **{
            f"bytes{size}": size * 8
            for size in range(1, 33)
        }
    }

    issue_type = issue_type_size.keys();

    def _detect(self) -> List[Output]:
        """"""
        results: List[Output] = []

        for contract in self.compilation_unit.contracts:
            if contract.is_library:
                continue
            for function in contract.functions:
                if function.contract_declarer != contract:
                    continue

                flagged_nodes = []

                for node in function.nodes:
                    
                    expr = str(node.expression)
                    if Truncation.skip_op.search(expr):
                        continue
                    for ir in node.irs:
                        if isinstance(ir, TypeConversion):
                            if isinstance(ir.variable, Constant):
                                continue
                            if is_dependent(ir.variable, SolidityVariable("now"), node):
                                continue
                            if is_dependent(ir.variable, SolidityVariableComposed("block.timestamp"), node):
                                continue
                            src_type = str(ir.variable.type)
                            tgt_type = str(ir.type)
                            
                            if src_type in Truncation.issue_type and tgt_type in  Truncation.issue_type:
                                src_bits = Truncation.issue_type_size.get(src_type)
                                tgt_bits = Truncation.issue_type_size.get(tgt_type)

                                if tgt_bits < src_bits:
                                    flagged_nodes.append(node)
                                    break

                if flagged_nodes:
                    info: DETECTOR_INFO = [function, " possible truncation in type conversion:- \n"]
                    for node in flagged_nodes:
                        info += ["\t- ", node, "\n"]

                    res = self.generate_result(info)
                    results.append(res)

            
        return results
