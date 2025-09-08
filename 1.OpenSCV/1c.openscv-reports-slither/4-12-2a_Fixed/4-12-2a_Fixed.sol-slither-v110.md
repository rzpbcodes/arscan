**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [uninitialized-state](#uninitialized-state) (1 results) (High)
 - [dead-code](#dead-code) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (2 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## uninitialized-state
Impact: High
Confidence: High
 - [ ] ID-0
[Bug.agora](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L4) is never initialized. It is used in:
	- [Bug.get_next_expiration(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L10-L12)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L4


## dead-code
Impact: Informational
Confidence: Medium
 - [ ] ID-1
[Bug.get_next_expiration(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L10-L12) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L10-L12


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
Version constraint ^0.4.24 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [^0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L1


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-4
Parameter [Bug.get_next_expiration(uint256).earlier_time](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L10) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L10


 - [ ] ID-5
Function [Bug.get_next_expiration(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L10-L12) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L10-L12


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-6
[Bug.agora](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L4) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-2a_Fixed/4-12-2a_Fixed.sol#L4


