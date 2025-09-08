**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [solc-version](#solc-version) (2 results) (Informational)
 - [naming-convention](#naming-convention) (1 results) (Informational)
## solc-version
Impact: Informational
Confidence: High
 - [ ] ID-0
Version constraint ^0.4.0 contains known severe issues (https://solidity.readthedocs.io/en/latest/bugs.html)
	- DirtyBytesArrayToStorage
	- KeccakCaching
	- EmptyByteArrayCopy
	- DynamicArrayCleanup
	- TupleAssignmentMultiStackSlotComponents
	- MemoryArrayCreationOverflow
	- privateCanBeOverridden
	- IncorrectEventSignatureInLibraries_0.4.x
	- ExpExponentCleanup
	- NestedArrayFunctionCallDecoder
	- ZeroFunctionSelector
	- DelegateCallReturnValue
	- ECRecoverMalformedInput
	- SkipEmptyStringLiteral
	- ConstantOptimizerSubtraction
	- IdentityPrecompileReturnIgnored
	- HighOrderByteCleanStorage
	- OptimizerStaleKnowledgeAboutSHA3
	- LibrariesNotCallableFromPayableFunctions.
It is used by:
	- [^0.4.0]()

 - [ ] ID-1
solc-0.4.0 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible.

## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-2
Contract [callExternalExample]() is not in CapWords

