**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [locked-ether](#locked-ether) (1 results) (Medium)
 - [shadowing-builtin](#shadowing-builtin) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
## locked-ether
Impact: Medium
Confidence: High
 - [ ] ID-0
Contract locking ether found:
	Contract [Locked](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Bug/4-7-1a_Bug.sol#L3-L7) has payable functions:
	 - [Locked.receive()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Bug/4-7-1a_Bug.sol#L4-L5)
	But does not have a function to withdraw the ether

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Bug/4-7-1a_Bug.sol#L3-L7


## shadowing-builtin
Impact: Low
Confidence: High
 - [ ] ID-1
[Locked.receive()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Bug/4-7-1a_Bug.sol#L4-L5) (function) shadows built-in symbol"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Bug/4-7-1a_Bug.sol#L4-L5


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
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
	- [0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Bug/4-7-1a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Bug/4-7-1a_Bug.sol#L1


