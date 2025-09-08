**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [tautology](#tautology) (1 results) (Medium)
 - [dead-code](#dead-code) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
## tautology
Impact: Medium
Confidence: High
 - [ ] ID-0
[TestLooping.looping()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-4a_Bug/4-6-4a_Bug.sol#L4-L8) contains a tautology or contradiction:
	- [i <= 256](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-4a_Bug/4-6-4a_Bug.sol#L5)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-4a_Bug/4-6-4a_Bug.sol#L4-L8


## dead-code
Impact: Informational
Confidence: Medium
 - [ ] ID-1
[TestLooping.looping()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-4a_Bug/4-6-4a_Bug.sol#L4-L8) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-4a_Bug/4-6-4a_Bug.sol#L4-L8


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
Version constraint 0.4.25 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-4a_Bug/4-6-4a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-4a_Bug/4-6-4a_Bug.sol#L1


