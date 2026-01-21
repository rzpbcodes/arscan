**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [locked-ether](#locked-ether) (1 results) (Medium)
 - [solc-version](#solc-version) (2 results) (Informational)
## locked-ether
Impact: Medium
Confidence: High
 - [ ] ID-0
Contract locking ether found:
	Contract [ExRedundant](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-11a_Bug/4-11a_Bug.sol#L6-L15) has payable functions:
	 - [ExRedundant.fallback()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-11a_Bug/4-11a_Bug.sol#L9-L12)
	But does not have a function to withdraw the ether

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-11a_Bug/4-11a_Bug.sol#L6-L15


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
Version constraint 0.5.0 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-11a_Bug/4-11a_Bug.sol#L4)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-11a_Bug/4-11a_Bug.sol#L4


