**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [incorrect-equality](#incorrect-equality) (1 results) (Medium)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (2 results) (Informational)
 - [reentrancy-unlimited-gas](#reentrancy-unlimited-gas) (1 results) (Informational)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[GuessTheNumber.checkAndTransferPrize(uint256,uint256,address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L30-L41) sends eth to arbitrary user
	Dangerous calls:
	- [guesser.transfer(p)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L34)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L30-L41


## incorrect-equality
Impact: Medium
Confidence: High
 - [ ] ID-1
[GuessTheNumber.checkAndTransferPrize(uint256,uint256,address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L30-L41) uses a dangerous strict equality:
	- [n == _secretNumber](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L32)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L30-L41


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
Version constraint ^0.5.0 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [^0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L1


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-4
Event [GuessTheNumber.success(string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L7) is not in CapWords

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L7


 - [ ] ID-5
Event [GuessTheNumber.wrongNumber(string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L8) is not in CapWords

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L8


## reentrancy-unlimited-gas
Impact: Informational
Confidence: Medium
 - [ ] ID-6
Reentrancy in [GuessTheNumber.checkAndTransferPrize(uint256,uint256,address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L30-L41):
	External calls:
	- [guesser.transfer(p)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L34)
	Event emitted after the call(s):
	- [success(You guessed the correct number!)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L35)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-4-3a_Fixed/4-4-3a_Fixed.sol#L30-L41


