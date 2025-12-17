"""
Test the enhanced _summarize_each_file functionality with function snippet extraction
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.software_profile import SoftwareProfiler
from core.config import ScannerConfig


def test_summarize_with_snippets():
    """Test that _summarize_each_file extracts function snippets"""
    
    # Create a simple test file
    test_code = '''
def hello_world():
    """A simple hello world function"""
    print("Hello, World!")
    return True

def process_data(data):
    """Process some data"""
    result = []
    for item in data:
        result.append(item * 2)
    return result

class MyClass:
    """A simple class"""
    def __init__(self):
        self.value = 0
    
    def increment(self):
        self.value += 1
'''
    
    # Test the AST extraction function directly without full profiler
    # Create a minimal profiler instance
    profiler = SoftwareProfiler(config=None, llm_client=None)
    
    # Test extracting hello_world function
    snippet = profiler._extract_function_snippet_based_on_name_with_ast(test_code, "hello_world")
    print("Extracted snippet for 'hello_world':")
    print(snippet)
    print("\n" + "="*80 + "\n")
    
    # Test extracting process_data function
    snippet = profiler._extract_function_snippet_based_on_name_with_ast(test_code, "process_data")
    print("Extracted snippet for 'process_data':")
    print(snippet)
    print("\n" + "="*80 + "\n")
    
    # Test extracting MyClass
    snippet = profiler._extract_function_snippet_based_on_name_with_ast(test_code, "MyClass")
    print("Extracted snippet for 'MyClass':")
    print(snippet)
    print("\n" + "="*80 + "\n")
    
    # Test non-existent function
    snippet = profiler._extract_function_snippet_based_on_name_with_ast(test_code, "non_existent")
    print(f"Non-existent function result: '{snippet}' (should be empty)")
    

if __name__ == "__main__":
    test_summarize_with_snippets()
