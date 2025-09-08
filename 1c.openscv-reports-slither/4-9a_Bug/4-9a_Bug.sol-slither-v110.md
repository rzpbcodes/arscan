**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [too-many-digits](#too-many-digits) (1 results) (Informational)
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
	- [^0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-9a_Bug/4-9a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-9a_Bug/4-9a_Bug.sol#L1


## too-many-digits
Impact: Informational
Confidence: Medium
 - [ ] ID-2
[MyContract.slitherConstructorVariables()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-9a_Bug/4-9a_Bug.sol#L3-L5) uses literals with too many digits:
	- [_ether = 10000000000000000000](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-9a_Bug/4-9a_Bug.sol#L4)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-9a_Bug/4-9a_Bug.sol#L3-L5


