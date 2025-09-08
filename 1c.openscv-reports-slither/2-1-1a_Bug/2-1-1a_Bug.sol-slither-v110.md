**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [solc-version](#solc-version) (2 results) (Informational)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[Vulnerable.withdraw(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Bug/2-1-1a_Bug.sol#L4-L8) sends eth to arbitrary user
	Dangerous calls:
	- [msg.sender.transfer(amount)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Bug/2-1-1a_Bug.sol#L7)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Bug/2-1-1a_Bug.sol#L4-L8


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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Bug/2-1-1a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Bug/2-1-1a_Bug.sol#L1


 - [ ] ID-2
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

