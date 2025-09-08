**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [missing-zero-check](#missing-zero-check) (1 results) (Low)
 - [solc-version](#solc-version) (2 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[Stateful.exploit(address)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L7-L11) sends eth to arbitrary user
	Dangerous calls:
	- [attacker.transfer(this.balance)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L10)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L7-L11


## missing-zero-check
Impact: Low
Confidence: Medium
 - [ ] ID-1
[Stateful.exploit(address).attacker](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L7) lacks a zero-check on :
		- [attacker.transfer(this.balance)](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L10)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L7


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
	- [0.4.25](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L1


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-4
[Stateful.vulnerable](../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L5) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/5-1-7a_Fixed/5-1-7a_Fixed.sol#L5


