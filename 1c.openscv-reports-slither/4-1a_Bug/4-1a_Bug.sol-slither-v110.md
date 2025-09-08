**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [incorrect-equality](#incorrect-equality) (2 results) (Medium)
 - [timestamp](#timestamp) (1 results) (Low)
 - [deprecated-standards](#deprecated-standards) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[GuessTheRandomNumberChallenge.guess(uint8)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L15-L21) sends eth to arbitrary user
	Dangerous calls:
	- [msg.sender.transfer(2000000000000000000)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L19)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L15-L21


## incorrect-equality
Impact: Medium
Confidence: High
 - [ ] ID-1
[GuessTheRandomNumberChallenge.guess(uint8)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L15-L21) uses a dangerous strict equality:
	- [n == answer](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L18)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L15-L21


 - [ ] ID-2
[GuessTheRandomNumberChallenge.isComplete()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L11-L13) uses a dangerous strict equality:
	- [address(this).balance == 0](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L12)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L11-L13


## timestamp
Impact: Low
Confidence: Medium
 - [ ] ID-3
[GuessTheRandomNumberChallenge.guess(uint8)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L15-L21) uses timestamp for comparisons
	Dangerous comparisons:
	- [n == answer](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L18)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L15-L21


## deprecated-standards
Impact: Informational
Confidence: High
 - [ ] ID-4
Deprecated standard detected [answer = uint8(keccak256()(block.blockhash(block.number - 1),now))](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L8):
	- Usage of "block.blockhash()" should be replaced with "blockhash()"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L8


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-5
Version constraint ^0.4.21 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- EventStructWrongData
	- NestedArrayFunctionCallDecoder.
It is used by:
	- [^0.4.21](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-1a_Bug/4-1a_Bug.sol#L1


 - [ ] ID-6
solc-0.4.21 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

