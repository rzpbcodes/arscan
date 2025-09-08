**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [incorrect-equality](#incorrect-equality) (2 results) (Medium)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
 - [unused-state](#unused-state) (1 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## incorrect-equality
Impact: Medium
Confidence: High
 - [ ] ID-0
[GuessTheRandomNumberChallenge.recover()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L24-L32) uses a dangerous strict equality:
	- [uint256(blockhash(uint256)(commitBlock + 20)) == commitedGuess](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L29)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L24-L32


 - [ ] ID-1
[GuessTheRandomNumberChallenge.isComplete()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L13-L15) uses a dangerous strict equality:
	- [address(this).balance == 0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L14)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L13-L15


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
Version constraint ^0.4.25 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [^0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L1


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-4
Parameter [GuessTheRandomNumberChallenge.guess(uint8)._guess](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L18) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L18


## unused-state
Impact: Informational
Confidence: High
 - [ ] ID-5
[GuessTheRandomNumberChallenge.answer](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L4) is never used in [GuessTheRandomNumberChallenge](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L3-L34)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L4


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-6
[GuessTheRandomNumberChallenge.answer](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L4) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Fixed/4-1a_Fixed.sol#L4


