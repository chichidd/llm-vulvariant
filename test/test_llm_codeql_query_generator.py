#!/usr/bin/env python3
"""
Test script for LLM CodeQL Query Generator
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.scanner.llm_generate_codeql_query import (
    CodeQLQueryGenerator,
    CodeQLQueryValidator,
    generate_codeql_query,
    QueryGenerationResult
)
from src.llm import LLMConfig, create_llm_client


def test_validator():
    """Test the CodeQL query validator"""
    print("="*60)
    print("Testing CodeQL Query Validator")
    print("="*60)
    
    validator = CodeQLQueryValidator(language="python")
    
    # Test 1: Valid query
    print("\n1. Testing valid query...")
    valid_query = """/**
 * @name Find os.system calls
 * @description Finds all calls to os.system()
 * @kind problem
 * @problem.severity warning
 * @id python/os-system-call
 */

import python

from Call call
where
  call.getFunc().(Attribute).getObject().(Name).getId() = "os" and
  call.getFunc().(Attribute).getAttr() = "system"
select call, "Call to os.system()"
"""
    is_valid, issues = validator.validate(valid_query)
    print(f"   Valid: {is_valid}")
    if issues:
        print(f"   Issues: {issues}")
    
    # Test 2: Invalid query (missing import)
    print("\n2. Testing invalid query (missing import)...")
    invalid_query = """/**
 * @name Find calls
 */

from Call call
select call
"""
    is_valid, issues = validator.validate(invalid_query)
    print(f"   Valid: {is_valid}")
    print(f"   Issues: {issues}")
    
    # Test 3: Auto-fix
    print("\n3. Testing auto-fix...")
    fixed_query, fixes = validator.fix_common_issues(invalid_query)
    print(f"   Fixes applied: {fixes}")
    is_valid, issues = validator.validate(fixed_query)
    print(f"   Now valid: {is_valid}")


def test_generator_basic():
    """Test basic query generation"""
    print("\n" + "="*60)
    print("Testing Basic Query Generation")
    print("="*60)
    
    # Create LLM client
    config = LLMConfig(provider='deepseek')
    llm_client = create_llm_client(config)
    
    # Create generator
    generator = CodeQLQueryGenerator(
        llm_client=llm_client,
        language="python",
        verbose=True
    )
    
    # Generate a simple query
    intent = "Find all calls to pickle.loads()"
    print(f"\nIntent: {intent}")
    
    result = generator.generate_query(
        intent=intent,
        max_retries=5  # Use fewer retries for testing
    )
    
    print(f"\nResult:")
    print(f"  Success: {result.success}")
    print(f"  Attempts: {result.attempts}")
    print(f"  Errors: {result.errors}")
    
    if result.success:
        print(f"\nGenerated Query:")
        print("-"*60)
        print(result.query)
        print("-"*60)
    else:
        print(f"\nValidation Issues: {result.validation_issues}")


def test_convenience_function():
    """Test the convenience function"""
    print("\n" + "="*60)
    print("Testing Convenience Function")
    print("="*60)
    
    intent = "Find all calls to os.system()"
    print(f"\nIntent: {intent}")
    
    success, query, errors = generate_codeql_query(
        intent=intent,
        language="python",
        max_retries=5,
        verbose=True
    )
    
    print(f"\nResult:")
    print(f"  Success: {success}")
    
    if success:
        print(f"\nGenerated Query:")
        print("-"*60)
        print(query)
        print("-"*60)
    else:
        print(f"  Errors: {errors}")


def test_with_context():
    """Test query generation with additional context"""
    print("\n" + "="*60)
    print("Testing Query Generation with Context")
    print("="*60)
    
    intent = "Find deserialization vulnerabilities"
    context = """
Look for patterns like:
- pickle.loads()
- pickle.load()
- yaml.load() with unsafe loader
- marshal.loads()

These are commonly used in deserialization attacks.
"""
    
    config = LLMConfig(provider='deepseek')
    llm_client = create_llm_client(config)
    
    generator = CodeQLQueryGenerator(
        llm_client=llm_client,
        language="python",
        verbose=True
    )
    
    print(f"Intent: {intent}")
    print(f"Context: {context.strip()}")
    
    result = generator.generate_query(
        intent=intent,
        context=context,
        max_retries=5
    )
    
    print(f"\nResult:")
    print(f"  Success: {result.success}")
    print(f"  Attempts: {result.attempts}")
    
    if result.success:
        print(f"\nGenerated Query:")
        print("-"*60)
        print(result.query)
        print("-"*60)


def main():
    """Run all tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test LLM CodeQL Query Generator')
    parser.add_argument('--test', choices=['validator', 'basic', 'convenience', 'context', 'all'],
                       default='all', help='Which test to run')
    args = parser.parse_args()
    
    tests = {
        'validator': test_validator,
        'basic': test_generator_basic,
        'convenience': test_convenience_function,
        'context': test_with_context,
    }
    
    if args.test == 'all':
        for test_name, test_func in tests.items():
            try:
                test_func()
            except Exception as e:
                print(f"\n✗ Test '{test_name}' failed: {e}")
                import traceback
                traceback.print_exc()
    else:
        try:
            tests[args.test]()
        except Exception as e:
            print(f"\n✗ Test failed: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*60)
    print("Testing Complete")
    print("="*60)


if __name__ == "__main__":
    main()
