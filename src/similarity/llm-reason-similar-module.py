"""
This file implements functions to compare two modules (M1, and M2) using LLMs.
The two modules can come from two different projects or codebases or from the same project.

The goal is to find similar (sub-)modules in M2 that correspond to the (sub-)modules in M1 in terms of functionality, structure, and purpose.

First, get an overview for two projects. 
The LLM can use the generate software profiles and the tools in this scripts to analyze the code structure, key files, and important functions/classes.
Based on this overview, identify the main modules in both projects. 

After that:
1. For each module classification and each (sub-)modules in this classification of the M1, identify the corresponding (sub-)modules in M2 that are similar in functionality and purpose.
2. The LLM starts from the top-level (sub-)modules in M1 and M2, and gradually goes deeper into the nested (sub-)modules.
3. The LLM identifies the call relationship and the semantics of each (sub-)module.
4. The LLM acts like an agent to automatically explore the two codebases with snippet/file/folder reading tools.
5. The LLM rechecks and makes sure that it has completed examinations on all the modules and the analysis has reached each files for both M1 and M2.
If and only if the LLM found that it has complete all the possible examinations on both M1 and M2, it can stop the process.

Finally, the LLM can generate a similarity report summarizing a list of the identified similar (sub-)modules between M1 and M2. For each pair of identified (sub-)modules, the report includes:
1. The corresponding classification scheme for the similar modules.
2. The involved folders/files/snippets in M1 and M2.
3. The similarity reasoning including why they are considered similar, what aspects are similar, and any notable differences.

"""

