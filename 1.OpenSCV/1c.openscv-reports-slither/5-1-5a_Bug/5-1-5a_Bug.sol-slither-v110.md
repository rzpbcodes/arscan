**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [events-maths](#events-maths) (2 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (2 results) (Informational)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[AmountSender.setTransferAmount(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L33-L34) sends eth to arbitrary user
	Dangerous calls:
	- [msg.sender.transfer(amount)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L34)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L33-L34


## events-maths
Impact: Low
Confidence: Medium
 - [ ] ID-1
[AmountSender.setAmountOp2(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L9-L13) should emit an event for: 
	- [amount = _amount](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L12) 

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L9-L13


 - [ ] ID-2
[AmountSender.setAmountOp1(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L15-L19) should emit an event for: 
	- [amount = _amount](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L18) 

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L15-L19


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-3
Version constraint ^0.4.18 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- ExpExponentCleanup
	- EventStructWrongData
	- NestedArrayFunctionCallDecoder.
It is used by:
	- [^0.4.18](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L1


 - [ ] ID-4
solc-0.4.18 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-5
Parameter [AmountSender.setAmountOp2(uint256)._amount](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L9) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L9


 - [ ] ID-6
Parameter [AmountSender.setAmountOp1(uint256)._amount](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L15) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-5a_Bug/5-1-5a_Bug.sol#L15


