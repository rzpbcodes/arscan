**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [uninitialized-state](#uninitialized-state) (1 results) (High)
 - [uninitialized-local](#uninitialized-local) (1 results) (Medium)
 - [dead-code](#dead-code) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
## uninitialized-state
Impact: High
Confidence: High
 - [ ] ID-0
[WhitelistedBuyers.whitelist](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L19) is never initialized. It is used in:
	- [WhitelistedBuyers.validPurchase()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L21-L24)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L19


## uninitialized-local
Impact: Medium
Confidence: Medium
 - [ ] ID-1
[Utils.validPurchase().cap](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L36) is a local variable never initialized

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L36


## dead-code
Impact: Informational
Confidence: Medium
 - [ ] ID-2
[Utils.validPurchase()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L34-L43) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L34-L43


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-3
solc-0.4.13 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-4
Version constraint 0.4.13 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
	- DirtyBytesArrayToStorage
	- KeccakCaching
	- EmptyByteArrayCopy
	- DynamicArrayCleanup
	- ImplicitConstructorCallvalueCheck
	- TupleAssignmentMultiStackSlotComponents
	- MemoryArrayCreationOverflow
	- privateCanBeOverridden
	- SignedArrayStorageCopy
	- UninitializedFunctionPointerInConstructor_0.4.x
	- IncorrectEventSignatureInLibraries_0.4.x
	- ExpExponentCleanup
	- NestedArrayFunctionCallDecoder
	- ZeroFunctionSelector
	- DelegateCallReturnValue
	- ECRecoverMalformedInput.
It is used by:
	- [0.4.13](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Bug/4-5a_Bug.sol#L1


