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


class Signedness(AbstractDetector):

    ARGUMENT = "signedness"
    HELP = "oscv-6.3.2"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "--"
    WIKI_TITLE = "--"
    WIKI_DESCRIPTION = "--"
    WIKI_EXPLOIT_SCENARIO = "--"
    WIKI_RECOMMENDATION = "--"

    signed_set   = set(Int)
    unsigned_set = set(Uint)
    int_set = (signed_set | unsigned_set)

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
                    for ir in node.irs:
                        if isinstance(ir, TypeConversion):
                            tgt = str(ir.type)
                            if not tgt in Signedness.int_set:
                                continue

                            src = str(ir.variable.type)
                            if not src in Signedness.int_set:
                                continue

                            if (src in Signedness.signed_set) ^ (tgt in Signedness.signed_set):
                                flagged_nodes.append(node)
                                break

                if flagged_nodes:
                    info: DETECTOR_INFO = [function, " possible signedness bug in type conversion:- \n"]
                    for node in flagged_nodes:
                        info += ["\t- ", node, "\n"]

                    res = self.generate_result(info)
                    results.append(res)

            
        return results