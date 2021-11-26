# resolve_function_hash
An old code I wrote which tries to resolve function hashes from a specific malware (I don't remember which). 

It can be reused, just have to reimplement the hashing function if it differs.

The script traverses the loaded DLLs in memory, hashes the functions in their export tables and comapres them to the hashes in the list.
If a match is found, it prints the result.

It can be rewritten to iterate through the DLLs in the system directory, in case the DLL in question is not loaded in memory of the current process.
This search would be slower though.
