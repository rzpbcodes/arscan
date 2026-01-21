**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
Version constraint ^0.5.10 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
	- AbiReencodingHeadOverflowWithStaticArrayCleanup
	- DirtyBytesArrayToStorage
	- NestedCalldataArrayAbiReencodingSizeValidation
	- ABIDecodeTwoDimensionalArrayMemory
	- KeccakCaching
	- EmptyByteArrayCopy
	- DynamicArrayCleanup
	- ImplicitConstructorCallvalueCheck
	- TupleAssignmentMultiStackSlotComponents
	- MemoryArrayCreationOverflow
	- privateCanBeOverridden
	- YulOptimizerRedundantAssignmentBreakContinue0.5
	- ABIEncoderV2CalldataStructsWithStaticallySizedAndDynamicallyEncodedMembers.
It is used by:
	- [^0.5.10](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-5a_Bug/4-6-5a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-5a_Bug/4-6-5a_Bug.sol#L1


 - [ ] ID-1
solc-0.5.10 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

