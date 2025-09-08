**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [void-cst](#void-cst) (3 results) (Low)
 - [solc-version](#solc-version) (1 results) (Informational)
 - [constable-states](#constable-states) (1 results) (Optimization)
## void-cst
Impact: Low
Confidence: High
 - [ ] ID-0
Void constructor called in [C.constructor(string,string)](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L27):
	- [X()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L27)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L27


 - [ ] ID-1
Void constructor called in [D.constructor()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L39):
	- [X()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L39)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L39


 - [ ] ID-2
Void constructor called in [E.constructor()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L47):
	- [X()](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L47)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L47


## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-3
Version constraint ^0.8.13 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
	- VerbatimInvalidDeduplication
	- FullInlinerNonExpressionSplitArgumentEvaluationOrder
	- MissingSideEffectsOnSelectorAccess
	- StorageWriteRemovalBeforeConditionalTermination
	- AbiReencodingHeadOverflowWithStaticArrayCleanup
	- DirtyBytesArrayToStorage
	- InlineAssemblyMemorySideEffects
	- DataLocationChangeInInternalOverride
	- NestedCalldataArrayAbiReencodingSizeValidation.
It is used by:
	- [^0.8.13](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L1)

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L1


## constable-states
Impact: Optimization
Confidence: High
 - [ ] ID-4
[X.name](../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L5) should be constant 

../../contracts/3.OpenSCV/openscv-subfolders-slither/4-7-2a_Bug/4-7-2a_Bug.sol#L5


