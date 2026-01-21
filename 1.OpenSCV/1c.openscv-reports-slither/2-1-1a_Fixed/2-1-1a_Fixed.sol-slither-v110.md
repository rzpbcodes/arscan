**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[Fixed.withdraw(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Fixed/2-1-1a_Fixed.sol#L4-L9) sends eth to arbitrary user
	Dangerous calls:
	- [success = msg.sender.call.value(amount)(100)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Fixed/2-1-1a_Fixed.sol#L7)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Fixed/2-1-1a_Fixed.sol#L4-L9


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-1
solc-0.4.25 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-2
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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Fixed/2-1-1a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Fixed/2-1-1a_Fixed.sol#L1


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-3
Low level call in [Fixed.withdraw(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Fixed/2-1-1a_Fixed.sol#L4-L9):
	- [success = msg.sender.call.value(amount)(100)](../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Fixed/2-1-1a_Fixed.sol#L7)

../../contracts/3.OpenSCV/openscv-subfolders-slither/2-1-1a_Fixed/2-1-1a_Fixed.sol#L4-L9


