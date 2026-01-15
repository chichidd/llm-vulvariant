"""Test hybrid module analyzer caching mechanism."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

from profiler.software.module_analyzer.hybrid import HybridModuleAnalyzer
from profiler.software.models import FolderModule


def create_mock_folder_module(folder_path: str, name: str, files: list, children: list = None):
    """Create a mock FolderModule."""
    module = FolderModule(
        name=name,
        folder_path=folder_path,
        files=files,
        children=children or [],
        depth=folder_path.count('/'),
        description=f"Mock module for {name}",
        key_functions=[],
        key_classes=[],
        external_dependencies=[],
        is_leaf=not children,
        full_module_path=folder_path,
    )
    return module


def test_hybrid_caching():
    """
    Test that hybrid analyzer correctly caches and reuses analyzed modules.
    
    Scenario:
    1. First coarse module has files in src/api/ -> analyzes src/
    2. Second coarse module has files in src/webui/ -> should reuse cached src/ and subfolders
    """
    print("\n" + "="*80)
    print("Testing Hybrid Module Analyzer Caching")
    print("="*80)
    
    # Mock LLM client
    mock_llm = MagicMock()
    
    # Create hybrid analyzer
    analyzer = HybridModuleAnalyzer(
        llm_client=mock_llm,
        max_agent_iterations=10,
        max_folder_iterations=10,
    )
    
    # Mock repo info - simulating LLaMA-Factory structure
    repo_info = {
        "files": [
            "src/api.py",
            "src/webui.py",
            "src/llamafactory/api/__init__.py",
            "src/llamafactory/api/app.py",
            "src/llamafactory/api/chat.py",
            "src/llamafactory/api/common.py",
            "src/llamafactory/api/protocol.py",
            "src/llamafactory/webui/__init__.py",
            "src/llamafactory/webui/interface.py",
            "src/llamafactory/webui/engine.py",
            "src/llamafactory/webui/manager.py",
            "src/llamafactory/webui/components/__init__.py",
            "src/llamafactory/webui/css.py",
            "src/llamafactory/webui/locales.py",
        ],
        "readme_content": "Test repository",
        "languages": {"Python": 100},
    }
    
    # Mock coarse-grained modules (from agent analysis)
    coarse_modules = [
        {
            "name": "API Module",
            "files": [
                "src/api.py",
                "src/llamafactory/api/__init__.py",
                "src/llamafactory/api/app.py",
                "src/llamafactory/api/chat.py",
                "src/llamafactory/api/common.py",
                "src/llamafactory/api/protocol.py",
            ],
            "description": "API related functionality"
        },
        {
            "name": "WebUI Module",
            "files": [
                "src/webui.py",
                "src/llamafactory/webui/__init__.py",
                "src/llamafactory/webui/interface.py",
                "src/llamafactory/webui/engine.py",
                "src/llamafactory/webui/manager.py",
                "src/llamafactory/webui/components/__init__.py",
                "src/llamafactory/webui/css.py",
                "src/llamafactory/webui/locales.py",
            ],
            "description": "Web UI functionality"
        }
    ]
    
    # Create a mock module tree structure for src/
    # This simulates what folder-based analysis would produce
    api_module = create_mock_folder_module(
        folder_path="src/llamafactory/api",
        name="api",
        files=[
            "src/llamafactory/api/__init__.py",
            "src/llamafactory/api/app.py",
            "src/llamafactory/api/chat.py",
            "src/llamafactory/api/common.py",
            "src/llamafactory/api/protocol.py",
        ],
    )
    
    webui_components_module = create_mock_folder_module(
        folder_path="src/llamafactory/webui/components",
        name="components",
        files=["src/llamafactory/webui/components/__init__.py"],
    )
    
    webui_module = create_mock_folder_module(
        folder_path="src/llamafactory/webui",
        name="webui",
        files=[
            "src/llamafactory/webui/__init__.py",
            "src/llamafactory/webui/interface.py",
            "src/llamafactory/webui/engine.py",
            "src/llamafactory/webui/manager.py",
            "src/llamafactory/webui/css.py",
            "src/llamafactory/webui/locales.py",
        ],
        children=[webui_components_module],
    )
    
    llamafactory_module = create_mock_folder_module(
        folder_path="src/llamafactory",
        name="llamafactory",
        files=[],
        children=[api_module, webui_module],
    )
    
    src_root_module = create_mock_folder_module(
        folder_path="src",
        name="src",
        files=["src/api.py", "src/webui.py"],
        children=[llamafactory_module],
    )
    
    # Track LLM calls
    llm_call_count = 0
    analyzed_folders = []
    
    def mock_analyze_module_folder(*args, **kwargs):
        """Mock the folder analysis method."""
        nonlocal llm_call_count, analyzed_folders
        
        folder_path = kwargs.get('folder_path', '')
        analyzed_folders.append(folder_path)
        
        print(f"\n📁 Analyzing folder: '{folder_path}'")
        
        # Only analyze src/ once, return the full structure
        if folder_path == "src":
            llm_call_count += 1
            print(f"  ✅ LLM analysis performed (call #{llm_call_count})")
            
            # Return the full module tree
            from profiler.software.models import ModuleTree
            
            total_modules = 6  # src, llamafactory, api, webui, components, files
            leaf_modules = 3   # api, webui/components, root files
            max_depth = 3
            
            return ModuleTree(
                root=src_root_module,
                repo_name="test-repo",
                repo_path="/tmp/test",
                analysis_timestamp=datetime.now().isoformat(),
                total_modules=total_modules,
                total_leaf_modules=leaf_modules,
                max_depth=max_depth,
                excluded_folders=[],
                code_extensions=[".py"],
            )
        else:
            print(f"  ⚠️ Unexpected folder analysis request: {folder_path}")
            return None
    
    # Patch the analyzer methods
    with patch.object(analyzer.agent_analyzer, 'analyze') as mock_agent_analyze:
        mock_agent_analyze.return_value = {
            "modules": coarse_modules,
            "llm_calls": 5,  # Simulate agent used 5 LLM calls
        }
        
        with patch.object(analyzer, '_analyze_module_folder', side_effect=mock_analyze_module_folder):
            # Run the hybrid analysis
            print("\n" + "-"*80)
            print("Starting Hybrid Analysis")
            print("-"*80)
            
            result = analyzer.analyze(
                repo_info=repo_info,
                repo_path=Path("/tmp/test-repo"),
                storage_manager=None,
                repo_name="test-repo",
                version="1.0",
            )
    
    # Verify results
    print("\n" + "-"*80)
    print("Verification Results")
    print("-"*80)
    
    print(f"\n✓ Coarse modules identified: {len(result['modules'])}")
    print(f"✓ Fine-grained results: {len(result['fine_grained_results'])}")
    print(f"✓ Folders analyzed: {analyzed_folders}")
    print(f"✓ LLM calls for folder analysis: {llm_call_count}")
    print(f"✓ Total LLM calls: {result['llm_calls']}")
    
    # Assert that src/ was only analyzed once
    assert llm_call_count == 1, f"Expected 1 LLM call, got {llm_call_count}"
    print("\n✅ SUCCESS: src/ was analyzed only once!")
    
    # Assert that analyzed_folders only contains "src" once
    assert analyzed_folders == ["src"], f"Expected ['src'], got {analyzed_folders}"
    print("✅ SUCCESS: Second module reused cached results!")
    
    # Check cache content
    print(f"\n📦 Cache contains {len(analyzer._stats)} entries")
    
    # Verify both modules got results
    assert "API Module" in result['fine_grained_results'], "API Module missing from results"
    assert "WebUI Module" in result['fine_grained_results'], "WebUI Module missing from results"
    print("✅ SUCCESS: Both modules have fine-grained results!")
    
    # Verify the modules are the same (reused)
    api_result = result['fine_grained_results']['API Module']
    webui_result = result['fine_grained_results']['WebUI Module']
    
    # They should have the same root module (src/)
    assert api_result.root.folder_path == "src", f"API result root path: {api_result.root.folder_path}"
    assert webui_result.root.folder_path == "src", f"WebUI result root path: {webui_result.root.folder_path}"
    print("✅ SUCCESS: Both modules share the same root (src/)!")
    
    print("\n" + "="*80)
    print("🎉 All Tests Passed!")
    print("="*80)
    print("\nSummary:")
    print(f"  • Analyzed {len(coarse_modules)} coarse-grained modules")
    print(f"  • Performed folder analysis {llm_call_count} time(s)")
    print(f"  • Reused cached results for subsequent modules")
    print(f"  • Total LLM calls: {result['llm_calls']}")


def test_subfolder_caching():
    """
    Test that hybrid analyzer reuses cached results for subfolders.
    
    Scenario:
    1. First coarse module has files in src/ -> analyzes src/ (and all subfolders)
    2. Second coarse module has files in src/llamafactory/api/ -> should reuse cached result
    3. Third coarse module has files in src/llamafactory/webui/ -> should reuse cached result
    """
    print("\n" + "="*80)
    print("Testing Subfolder Caching")
    print("="*80)
    
    # Mock LLM client
    mock_llm = MagicMock()
    
    # Create hybrid analyzer
    analyzer = HybridModuleAnalyzer(
        llm_client=mock_llm,
        max_agent_iterations=10,
        max_folder_iterations=10,
    )
    
    # Mock repo info - three modules with different parent folders
    repo_info = {
        "files": [
            "src/api.py",
            "src/webui.py",
            "src/llamafactory/api/__init__.py",
            "src/llamafactory/api/app.py",
            "src/llamafactory/webui/__init__.py",
            "src/llamafactory/webui/interface.py",
        ],
        "readme_content": "Test repository",
        "languages": {"Python": 100},
    }
    
    # Mock coarse-grained modules
    coarse_modules = [
        {
            "name": "Core Module",
            "files": ["src/api.py", "src/webui.py"],
            "description": "Core functionality"
        },
        {
            "name": "API Module",
            "files": [
                "src/llamafactory/api/__init__.py",
                "src/llamafactory/api/app.py",
            ],
            "description": "API functionality"
        },
        {
            "name": "WebUI Module",
            "files": [
                "src/llamafactory/webui/__init__.py",
                "src/llamafactory/webui/interface.py",
            ],
            "description": "Web UI functionality"
        }
    ]
    
    # Create mock module tree
    api_module = create_mock_folder_module(
        folder_path="src/llamafactory/api",
        name="api",
        files=["src/llamafactory/api/__init__.py", "src/llamafactory/api/app.py"],
    )
    
    webui_module = create_mock_folder_module(
        folder_path="src/llamafactory/webui",
        name="webui",
        files=["src/llamafactory/webui/__init__.py", "src/llamafactory/webui/interface.py"],
    )
    
    llamafactory_module = create_mock_folder_module(
        folder_path="src/llamafactory",
        name="llamafactory",
        files=[],
        children=[api_module, webui_module],
    )
    
    src_root_module = create_mock_folder_module(
        folder_path="src",
        name="src",
        files=["src/api.py", "src/webui.py"],
        children=[llamafactory_module],
    )
    
    # Track LLM calls
    llm_call_count = 0
    analyzed_folders = []
    
    def mock_analyze_module_folder(*args, **kwargs):
        """Mock the folder analysis method."""
        nonlocal llm_call_count, analyzed_folders
        
        folder_path = kwargs.get('folder_path', '')
        analyzed_folders.append(folder_path)
        
        print(f"\n📁 Analyzing folder: '{folder_path}'")
        
        # Only analyze src/ once
        if folder_path == "src":
            llm_call_count += 1
            print(f"  ✅ LLM analysis performed (call #{llm_call_count})")
            
            from profiler.software.models import ModuleTree
            
            return ModuleTree(
                root=src_root_module,
                repo_name="test-repo",
                repo_path="/tmp/test",
                analysis_timestamp=datetime.now().isoformat(),
                total_modules=5,
                total_leaf_modules=3,
                max_depth=3,
                excluded_folders=[],
                code_extensions=[".py"],
            )
        else:
            print(f"  ⚠️ Unexpected folder analysis: {folder_path}")
            return None
    
    # Patch the analyzer
    with patch.object(analyzer.agent_analyzer, 'analyze') as mock_agent_analyze:
        mock_agent_analyze.return_value = {
            "modules": coarse_modules,
            "llm_calls": 3,
        }
        
        with patch.object(analyzer, '_analyze_module_folder', side_effect=mock_analyze_module_folder):
            print("\n" + "-"*80)
            print("Starting Analysis")
            print("-"*80)
            
            result = analyzer.analyze(
                repo_info=repo_info,
                repo_path=Path("/tmp/test-repo"),
                storage_manager=None,
                repo_name="test-repo",
                version="1.0",
            )
    
    # Verify results
    print("\n" + "-"*80)
    print("Verification Results")
    print("-"*80)
    
    print(f"\n✓ Coarse modules: {len(result['modules'])}")
    print(f"✓ Fine-grained results: {len(result['fine_grained_results'])}")
    print(f"✓ Folders analyzed: {analyzed_folders}")
    print(f"✓ LLM calls: {llm_call_count}")
    
    # Assert only one folder was analyzed
    assert llm_call_count == 1, f"Expected 1 LLM call, got {llm_call_count}"
    assert analyzed_folders == ["src"], f"Expected ['src'], got {analyzed_folders}"
    print("\n✅ SUCCESS: Only src/ was analyzed, subfolders reused cache!")
    
    # All three modules should have results
    assert len(result['fine_grained_results']) == 3
    print("✅ SUCCESS: All three modules got results!")
    
    print("\n" + "="*80)
    print("🎉 Subfolder Caching Test Passed!")
    print("="*80)


if __name__ == "__main__":
    test_hybrid_caching()
    test_subfolder_caching()
