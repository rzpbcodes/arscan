**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [events-maths](#events-maths) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [reentrancy-unlimited-gas](#reentrancy-unlimited-gas) (2 results) (Informational)
## events-maths
Impact: Low
Confidence: Medium
 - [ ] ID-0
[EthTxOrderDependenceMinimal.setReward()](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L13-L19) should emit an event for: 
	- [reward = msg.value](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L18) 

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L13-L19


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.5.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
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
	- [^0.5.0](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L1


## reentrancy-unlimited-gas
Impact: Informational
Confidence: Medium
 - [ ] ID-3
Reentrancy in [EthTxOrderDependenceMinimal.claimReward(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L21-L27):
	External calls:
	- [msg.sender.transfer(reward)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L25)
	State variables written after the call(s):
	- [claimed = true](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L26)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L21-L27


 - [ ] ID-4
Reentrancy in [EthTxOrderDependenceMinimal.setReward()](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L13-L19):
	External calls:
	- [owner.transfer(reward)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L17)
	State variables written after the call(s):
	- [reward = msg.value](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L18)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-2a_Bug/5-1-2a_Bug.sol#L13-L19


