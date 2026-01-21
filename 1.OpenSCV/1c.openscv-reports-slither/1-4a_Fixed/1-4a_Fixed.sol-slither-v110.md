**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
 - [reentrancy-unlimited-gas](#reentrancy-unlimited-gas) (1 results) (Informational)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L1


 - [ ] ID-1
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-2
Contract [bid](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L3-L26) is not in CapWords

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L3-L26


## reentrancy-unlimited-gas
Impact: Informational
Confidence: Medium
 - [ ] ID-3
Reentrancy in [bid.withdraw(uint256,address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L12-L25):
	External calls:
	- [msg.sender.transfer(amount)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L19)
	- [msg.sender.transfer(amount - highestBid)](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L20)
	State variables written after the call(s):
	- [pendingReturns[msg.sender] = 0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L21)
	- [state = 0](../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L24)

../../contracts/3.OpenSCV/openscv-subfolders-slither/1-4a_Fixed/1-4a_Fixed.sol#L12-L25


