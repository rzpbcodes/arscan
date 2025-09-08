**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
solc-0.4.18 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-1
Version constraint ^0.4.18 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- ExpExponentCleanup
	- EventStructWrongData
	- NestedArrayFunctionCallDecoder.
It is used by:
	- [^0.4.18](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-4a_Bug/5-1-4a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-4a_Bug/5-1-4a_Bug.sol#L1


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-2
Parameter [TransactionOrdering.setPrice(uint256)._price](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-4a_Bug/5-1-4a_Bug.sol#L26) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-4a_Bug/5-1-4a_Bug.sol#L26


