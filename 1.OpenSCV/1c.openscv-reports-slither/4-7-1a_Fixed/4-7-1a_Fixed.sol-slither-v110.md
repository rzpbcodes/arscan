**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [shadowing-builtin](#shadowing-builtin) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
## shadowing-builtin
Impact: Low
Confidence: High
 - [ ] ID-0
[Locked.receive()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Fixed/4-7-1a_Fixed.sol#L4-L5) (function) shadows built-in symbol"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Fixed/4-7-1a_Fixed.sol#L4-L5


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
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
	- [0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Fixed/4-7-1a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-1a_Fixed/4-7-1a_Fixed.sol#L1


