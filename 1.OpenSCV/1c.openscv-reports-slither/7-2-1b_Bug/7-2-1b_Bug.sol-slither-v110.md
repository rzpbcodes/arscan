**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [missing-zero-check](#missing-zero-check) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (2 results) (Informational)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[Vault.unlock(address,bytes32)](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L11-L15) sends eth to arbitrary user
	Dangerous calls:
	- [_owner.transfer(this.balance)](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L13)

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L11-L15


## missing-zero-check
Impact: Low
Confidence: Medium
 - [ ] ID-1
[Vault.unlock(address,bytes32)._owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L11) lacks a zero-check on :
		- [_owner.transfer(this.balance)](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L13)

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L11


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.4.18 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
Version constraint 0.4.18 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
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
	- [0.4.18](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L1


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-4
Parameter [Vault.unlock(address,bytes32)._owner](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L11) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L11


 - [ ] ID-5
Parameter [Vault.unlock(address,bytes32)._password](../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L11) is not in mixedCase

../../contracts/3.OpenSCV/openscv-subfolders-slither/7-2-1b_Bug/7-2-1b_Bug.sol#L11


