**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [shadowing-local](#shadowing-local) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (3 results) (Informational)
 - [unused-state](#unused-state) (1 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## shadowing-local
Impact: Low
Confidence: High
 - [ ] ID-0
[Bug.alternate_sensitive_function().owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L13) shadows:
	- [Bug.owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L5) (state variable)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L13


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
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
	- [^0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L1


 - [ ] ID-2
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-3
Function [Bug.sensitive_function(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L7-L10) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L7-L10


 - [ ] ID-4
Function [Bug.alternate_sensitive_function()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L12-L16) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L12-L16


 - [ ] ID-5
Parameter [Bug.sensitive_function(address).p_owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L7) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L7


## unused-state
Impact: Informational
Confidence: High
 - [ ] ID-6
[Bug.owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L5) is never used in [Bug](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L4-L18)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L5


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-7
[Bug.owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L5) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-12-3a_Fixed/4-12-3a_Fixed.sol#L5


