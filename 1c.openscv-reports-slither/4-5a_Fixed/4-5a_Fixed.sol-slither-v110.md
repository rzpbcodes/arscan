**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [uninitialized-local](#uninitialized-local) (1 results) (Medium)
 - [dead-code](#dead-code) (1 results) (Informational)
 - [solc-version](#solc-version) (2 results) (Informational)
## uninitialized-local
Impact: Medium
Confidence: Medium
 - [ ] ID-0
[Utils.validPurchase().cap](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Fixed/4-5a_Fixed.sol#L36) is a local variable never initialized

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Fixed/4-5a_Fixed.sol#L36


## dead-code
Impact: Informational
Confidence: Medium
 - [ ] ID-1
[WhitelistedBuyers.validPurchase()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Fixed/4-5a_Fixed.sol#L21-L24) is never used and should be removed

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Fixed/4-5a_Fixed.sol#L21-L24


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-2
solc-0.4.13 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

 - [ ] ID-3
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
	- [0.4.13](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Fixed/4-5a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-5a_Fixed/4-5a_Fixed.sol#L1


