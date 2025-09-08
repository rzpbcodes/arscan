**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [unchecked-send](#unchecked-send) (1 results) (Medium)
 - [solc-version](#solc-version) (2 results) (Informational)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[Test.pay()](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-1a_Bug/5-1-1a_Bug.sol#L6-L8) sends eth to arbitrary user
	Dangerous calls:
	- [msg.sender.send(100)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-1a_Bug/5-1-1a_Bug.sol#L8)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-1a_Bug/5-1-1a_Bug.sol#L6-L8


## unchecked-send
Impact: Medium
Confidence: Medium
 - [ ] ID-1
[Test.pay()](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-1a_Bug/5-1-1a_Bug.sol#L6-L8) ignores return value by [msg.sender.send(100)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-1a_Bug/5-1-1a_Bug.sol#L8)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-1a_Bug/5-1-1a_Bug.sol#L6-L8


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-1a_Bug/5-1-1a_Bug.sol#L2)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-1a_Bug/5-1-1a_Bug.sol#L2


