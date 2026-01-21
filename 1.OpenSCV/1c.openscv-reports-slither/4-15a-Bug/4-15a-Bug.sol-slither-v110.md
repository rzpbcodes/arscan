**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [incorrect-unary](#incorrect-unary) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
## incorrect-unary
Impact: Low
Confidence: Medium
 - [ ] ID-0
[TypoOneCommand.alwaysOne()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-15a-Bug/4-15a-Bug.sol#L6-L8) uses an dangerous unary operator: [numberOne = + 1](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-15a-Bug/4-15a-Bug.sol#L7)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-15a-Bug/4-15a-Bug.sol#L6-L8


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
Version constraint ^0.4.25 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- UninitializedFunctionPointerInConstructor_0.4.x
	- IncorrectEventSignatureInLibraries_0.4.x
	- ABIEncoderV2PackedStorage_0.4.x.
It is used by:
	- [^0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-15a-Bug/4-15a-Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-15a-Bug/4-15a-Bug.sol#L1


