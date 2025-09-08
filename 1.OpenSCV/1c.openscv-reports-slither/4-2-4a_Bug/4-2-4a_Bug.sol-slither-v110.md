**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [uninitialized-storage](#uninitialized-storage) (1 results) (High)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (2 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
 - [external-function](#external-function) (1 results) (Optimization)
## uninitialized-storage
Impact: High
Confidence: High
 - [ ] ID-0
[PaySupplier.TransferMoney(string).newTransfer](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L13) is a storage variable never initialized

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L13


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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L1


 - [ ] ID-2
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-3
Function [PaySupplier.TransferMoney(string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L12-L16) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L12-L16


 - [ ] ID-4
Parameter [PaySupplier.TransferMoney(string)._name](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L12) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L12


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-5
[PaySupplier.unlocked](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L6) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L6


## external-function
Impact: Optimization
Confidence: High
 - [ ] ID-6
TransferMoney(string) should be declared external:
	- [PaySupplier.TransferMoney(string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L12-L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-2-4a_Bug/4-2-4a_Bug.sol#L12-L16


