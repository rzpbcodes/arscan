**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [suicidal](#suicidal) (1 results) (High)
 - [unchecked-lowlevel](#unchecked-lowlevel) (1 results) (Medium)
 - [shadowing-builtin](#shadowing-builtin) (1 results) (Low)
 - [deprecated-standards](#deprecated-standards) (6 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [low-level-calls](#low-level-calls) (1 results) (Informational)
## suicidal
Impact: High
Confidence: High
 - [ ] ID-0
[DeprecatedSimple.useDeprecated()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L7-L25) allows anyone to destruct the contract

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L7-L25


## unchecked-lowlevel
Impact: Medium
Confidence: Medium
 - [ ] ID-1
[DeprecatedSimple.useDeprecated()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L7-L25) ignores return value by [address(this).callcode()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L18)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L7-L25


## shadowing-builtin
Impact: Low
Confidence: High
 - [ ] ID-2
[DeprecatedSimple.useDeprecated().blockhash](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L9) (local variable) shadows built-in symbol"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L9


## deprecated-standards
Impact: Informational
Confidence: High
 - [ ] ID-3
Deprecated standard detected [gas = msg.gas](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L12):
	- Usage of "msg.gas" should be replaced with "gasleft()"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L12


 - [ ] ID-4
Deprecated standard detected [suicide(address)(address(0))](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L24):
	- Usage of "suicide()" should be replaced with "selfdestruct()"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L24


 - [ ] ID-5
Deprecated standard detected [THROW](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L15):
	- Usage of "throw" should be replaced with "revert()"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L15


 - [ ] ID-6
Deprecated standard detected [hashofhash = sha3()(blockhash)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L10):
	- Usage of "sha3()" should be replaced with "keccak256()"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L10


 - [ ] ID-7
Deprecated standard detected [blockhash = block.blockhash(0)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L9):
	- Usage of "block.blockhash()" should be replaced with "blockhash()"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L9


 - [ ] ID-8
Deprecated standard detected [address(this).callcode()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L18):
	- Usage of "callcode" should be replaced with "delegatecall"

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L18


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-9
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-10
Version constraint ^0.4.24 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [^0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L1


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-11
Low level call in [DeprecatedSimple.useDeprecated()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L7-L25):
	- [address(this).callcode()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L18)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-8-3a-Bug/4-8-3a-Bug.sol#L7-L25


