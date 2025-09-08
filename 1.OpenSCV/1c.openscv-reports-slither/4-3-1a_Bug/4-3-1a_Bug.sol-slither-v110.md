**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [unchecked-send](#unchecked-send) (1 results) (Medium)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [reentrancy-unlimited-gas](#reentrancy-unlimited-gas) (1 results) (Informational)
## unchecked-send
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[SimpleBank.withdraw()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L6-L9) ignores return value by [msg.sender.send(balances[msg.sender])](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L7)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L6-L9


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
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
	- [0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L1


## reentrancy-unlimited-gas
Impact: Informational
Confidence: Medium
 - [ ] ID-3
Reentrancy in [SimpleBank.withdraw()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L6-L9):
	External calls:
	- [msg.sender.send(balances[msg.sender])](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L7)
	State variables written after the call(s):
	- [balances[msg.sender] = 0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L8)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-3-1a_Bug/4-3-1a_Bug.sol#L6-L9


