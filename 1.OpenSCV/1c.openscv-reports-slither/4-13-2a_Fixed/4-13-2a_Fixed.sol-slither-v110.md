**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [controlled-array-length](#controlled-array-length) (1 results) (High)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (3 results) (Informational)
 - [unused-state](#unused-state) (1 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## controlled-array-length
Impact: High
Confidence: Medium
 - [ ] ID-0
[Wallet](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L3-L16) contract sets array length with a user-controlled value:
	- [bonusCodes.push(c)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L8)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L3-L16


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
	- [0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L1


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-3
Function [Wallet.UpdateBonusCodeAt(uint256,uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L12-L14) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L12-L14


 - [ ] ID-4
Function [Wallet.PopBonusCode()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L9-L11) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L9-L11


 - [ ] ID-5
Function [Wallet.PushBonusCode(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L7-L8) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L7-L8


## unused-state
Impact: Informational
Confidence: High
 - [ ] ID-6
[Wallet.owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L5) is never used in [Wallet](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L3-L16)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L5


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-7
[Wallet.owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L5) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-13-2a_Fixed/4-13-2a_Fixed.sol#L5


