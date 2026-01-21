**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [uninitialized-state](#uninitialized-state) (1 results) (High)
 - [constant-function-asm](#constant-function-asm) (1 results) (Medium)
 - [assembly](#assembly) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
 - [unused-state](#unused-state) (1 results) (Informational)
## uninitialized-state
Impact: High
Confidence: High
 - [ ] ID-0
[ERC721._tokenOwner](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L34) is never initialized. It is used in:
	- [ERC721.ownerOf(uint256)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L63-L67)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L34


## constant-function-asm
Impact: Medium
Confidence: Medium
 - [ ] ID-1
[Address.isContract(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L18-L29) is declared view but contains assembly code

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L18-L29


## assembly
Impact: Informational
Confidence: High
 - [ ] ID-2
[Address.isContract(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L18-L29) uses assembly
	- [INLINE ASM](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L27-L28)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L18-L29


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-3
solc-0.4.24 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-4
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
	- [^0.4.24](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L1


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-5
Constant [ERC721._InterfaceId_ERC721](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L37) is not in UPPER_CASE_WITH_UNDERSCORES

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L37


## unused-state
Impact: Informational
Confidence: High
 - [ ] ID-6
[ERC721._InterfaceId_ERC721](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L37) is never used in [ERC721](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L32-L72)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-6-2a_Bug/4-6-2a_Bug.sol#L37


