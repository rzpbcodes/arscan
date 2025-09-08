**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
 - [reentrancy-unlimited-gas](#reentrancy-unlimited-gas) (1 results) (Informational)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-1
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
	- [0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L1


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-2
Contract [auction](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L3-L15) is not in CapWords

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L3-L15


## reentrancy-unlimited-gas
Impact: Informational
Confidence: Medium
 - [ ] ID-3
Reentrancy in [auction.bid()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L7-L14):
	External calls:
	- [highestBidder.transfer(highestBid)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L10)
	State variables written after the call(s):
	- [highestBid = msg.value](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L13)
	- [highestBidder = msg.sender](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L12)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-3a_Bug/4-3-3a_Bug.sol#L7-L14


