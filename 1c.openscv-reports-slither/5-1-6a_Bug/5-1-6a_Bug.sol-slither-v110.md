**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [missing-zero-check](#missing-zero-check) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (2 results) (Informational)
## missing-zero-check
Impact: Low
Confidence: Medium
 - [ ] ID-0
[OwnableWallet.initWallet(address)._owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L6) lacks a zero-check on :
		- [owner = _owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L7)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L6


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
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
	- [0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L1


 - [ ] ID-2
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-3
Parameter [OwnableWallet.withdraw(uint256)._amount](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L11) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L11


 - [ ] ID-4
Parameter [OwnableWallet.initWallet(address)._owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L6) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-6a_Bug/5-1-6a_Bug.sol#L6


