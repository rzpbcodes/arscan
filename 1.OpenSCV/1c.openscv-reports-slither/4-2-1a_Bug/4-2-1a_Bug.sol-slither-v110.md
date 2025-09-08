**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [uninitialized-state](#uninitialized-state) (1 results) (High)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## uninitialized-state
Impact: High
Confidence: High
 - [ ] ID-0
[Missing.owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-1a_Bug/4-2-1a_Bug.sol#L5) is never initialized. It is used in:
	- [Missing.withdraw()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-1a_Bug/4-2-1a_Bug.sol#L21-L31)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-1a_Bug/4-2-1a_Bug.sol#L5


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-1a_Bug/4-2-1a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-1a_Bug/4-2-1a_Bug.sol#L1


 - [ ] ID-2
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-3
[Missing.owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-1a_Bug/4-2-1a_Bug.sol#L5) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-1a_Bug/4-2-1a_Bug.sol#L5


