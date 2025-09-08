**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-1
Version constraint ^0.5.0 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
	- DirtyBytesArrayToStorage
	- ABIDecodeTwoDimensionalArrayMemory
	- KeccakCaching
	- EmptyByteArrayCopy
	- DynamicArrayCleanup
	- ImplicitConstructorCallvalueCheck
	- TupleAssignmentMultiStackSlotComponents
	- MemoryArrayCreationOverflow
	- privateCanBeOverridden
	- SignedArrayStorageCopy
	- ABIEncoderV2StorageArrayWithMultiSlotElement
	- DynamicConstructorArgumentsClippedABIV2
	- UninitializedFunctionPointerInConstructor
	- IncorrectEventSignatureInLibraries
	- ABIEncoderV2PackedStorage.
It is used by:
	- [^0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-3a_Bug/4-7-3a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-3a_Bug/4-7-3a_Bug.sol#L1


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-2
[UnusedVariables.a](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-3a_Bug/4-7-3a_Bug.sol#L4) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-3a_Bug/4-7-3a_Bug.sol#L4


