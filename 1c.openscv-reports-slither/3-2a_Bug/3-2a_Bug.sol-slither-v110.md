**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [unchecked-lowlevel](#unchecked-lowlevel) (1 results) (Medium)
 - [unchecked-send](#unchecked-send) (1 results) (Medium)
 - [function-init-state](#function-init-state) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[HardcodedNotGood.callLowLevel()](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L23-L25) ignores return value by [_callable.call.value(0).gas(10000)()](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L24)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L23-L25


## unchecked-send
Impact: Medium
Confidence: Medium
 - [ ] ID-1
[HardcodedNotGood.doSend(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L19-L21) ignores return value by [_callable.send(amount)](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L20)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L19-L21


## function-init-state
Impact: Informational
Confidence: High
 - [ ] ID-2
[HardcodedNotGood.callable](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L10) is set pre-construction with a non-constant function or state variable:
	- ICallable(_callable)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L10


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-3
solc-0.6.4 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-4
Version constraint 0.6.4 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
	- MissingSideEffectsOnSelectorAccess
	- AbiReencodingHeadOverflowWithStaticArrayCleanup
	- DirtyBytesArrayToStorage
	- NestedCalldataArrayAbiReencodingSizeValidation
	- ABIDecodeTwoDimensionalArrayMemory
	- KeccakCaching
	- EmptyByteArrayCopy
	- DynamicArrayCleanup
	- MissingEscapingInFormatting
	- ArraySliceDynamicallyEncodedBaseType
	- ImplicitConstructorCallvalueCheck
	- TupleAssignmentMultiStackSlotComponents
	- MemoryArrayCreationOverflow.
It is used by:
	- [0.6.4](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L1


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-5
Low level call in [HardcodedNotGood.callLowLevel()](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L23-L25):
	- [_callable.call.value(0).gas(10000)()](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L24)

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L23-L25


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-6
[HardcodedNotGood._callable](../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L9) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/3-2a_Bug/3-2a_Bug.sol#L9


