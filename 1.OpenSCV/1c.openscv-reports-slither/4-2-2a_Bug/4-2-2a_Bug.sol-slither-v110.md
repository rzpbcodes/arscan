**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
Version constraint 0.4.24 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- ABIEncoderV2PackedStorage_0.4.x
	- ExpExponentCleanup
	- EventStructWrongData.
It is used by:
	- [0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-2a_Bug/4-2-2a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-2a_Bug/4-2-2a_Bug.sol#L1


 - [ ] ID-1
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-2
Function [Missing.Constructor()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-2a_Bug/4-2-2a_Bug.sol#L11-L15) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-2a_Bug/4-2-2a_Bug.sol#L11-L15


