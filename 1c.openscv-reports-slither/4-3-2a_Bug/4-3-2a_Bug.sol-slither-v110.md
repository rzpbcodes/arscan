**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (2 results) (Informational)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
Version constraint ^0.4.23 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [^0.4.23](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-2a_Bug/4-3-2a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-2a_Bug/4-3-2a_Bug.sol#L1


 - [ ] ID-1
solc-0.4.23 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-2
Parameter [MultiOwnable.newOwner(address)._owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-2a_Bug/4-3-2a_Bug.sol#L31) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-2a_Bug/4-3-2a_Bug.sol#L31


 - [ ] ID-3
Parameter [MultiOwnable.deleteOwner(address)._owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-2a_Bug/4-3-2a_Bug.sol#L40) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-2a_Bug/4-3-2a_Bug.sol#L40


