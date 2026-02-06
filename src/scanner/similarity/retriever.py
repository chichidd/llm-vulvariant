"""
llm-vulvariant.src.scanner.similarity.retriever 的 Docstring
name: str
description: str
target_application: list
target_user: list
repo_info['readme_content']


"""


from scanner.similarity.embedding import EmbeddingRetriever, EmbeddingRetrievalConfig
from profiler.software.models import SoftwareProfile, ModuleInfo
from typing import Tuple
from pathlib import Path



class SimilarityRetriever:

    def __init__(self, embedding_config: EmbeddingRetrievalConfig=None):
        self.embedding_config = EmbeddingRetrievalConfig()
        if embedding_config:
            self.embedding_config = embedding_config
        self.text_retriever = EmbeddingRetriever(config=self.embedding_config)
        pass

        
    def compute_profile_similarity(
        self,
        profile1: SoftwareProfile, 
        profile2: SoftwareProfile, 
    ) -> Tuple[float, float, float, float]:
        """
        Compute four similarity scores between two software profiles.
        
        Args:
            profile1: First software profile
            profile2: Second software profile
   
        Returns:
            Tuple of (desc_sim, apps_sim, users_sim, module_jaccard_sim)
            - desc_sim: Description similarity (embedding-based)
            - apps_sim: Target applications similarity (embedding-based)
            - users_sim: Target users similarity (embedding-based)
            - module_jaccard_sim: Module Jaccard similarity (|intersection| / |union|)
        """
        # Description similarity
        desc_sim = self.text_retriever.similarity(profile1.description, profile2.description)
        
        # Target applications similarity
        apps1 = " | ".join(profile1.target_application)
        apps2 = " | ".join(profile2.target_application)
        if apps1 and apps2:
            apps_sim = self.text_retriever.similarity(apps1, apps2)
        else:
            apps_sim = 0.0
        
        # Target users similarity
        users1 = " | ".join(profile1.target_user)
        users2 = " | ".join(profile2.target_user)
        if users1 and users2:
            users_sim = self.text_retriever.similarity(users1, users2)
        else:
            users_sim = 0.0
        
        # Module Jaccard similarity (intersection / union)
        modules1 = set(m.name for m in profile1.modules)
        modules2 = set(m.name for m in profile2.modules)
        common_modules = modules1 & modules2
        union = modules1 | modules2
        if len(union) > 0:
            module_jaccard_sim = len(common_modules) / len(union)
        else:
            module_jaccard_sim = 0.0
        
        return {'description_sim': desc_sim, 
                'aaplication_sim': apps_sim, 
                'user_sim': users_sim, 
                'module_jaccard': module_jaccard_sim, 
                'common_modules': common_modules
                }




# from scanner.similarity.retriever import find_similar_modules_across_repos
# # Example usage: Find similar modules for the first repository
# source_repo_key = list(repo_similarity_dict.keys())[3]
# print(f"\nAnalyzing: {source_repo_key}\n")

# results = find_similar_modules_across_repos(
#     source_repo_label=source_repo_key,
#     repo_similarity_dict=repo_similarity_dict,
#     all_profiles=all_profiles,
#     text_retriever=text_retriever,
#     top_k=3,
#     module_similarity_threshold=0.7
# )

# print("\n" + "="*100)
# print("SUMMARY OF MODULE SIMILARITY RESULTS")
# print("="*100)
# for target_label, data in results.items():
#     print(f"\n{target_label}:")
#     print(f"  Repository Similarity (avg): {data['repo_info']['repo_similarity']['avg']:.4f}")
#     print(f"  Similar Module Pairs Found: {data['num_pairs']}")
#     if data['num_pairs'] > 0:
#         top_pair = data['similar_pairs'][0]
#         print(f"  Top Module Match: {top_pair['source_module'].name} <-> {top_pair['target_module'].name} ({top_pair['similarity']:.4f})")



def find_similar_modules_across_repos(
    source_repo_label: str,
    repo_similarity_dict: dict,
    all_profiles: dict,
    text_retriever: EmbeddingRetriever,
    top_k: int = 3,
    module_similarity_threshold: float = 0.7
):
    """
    Find similar modules between a source repo and its top-k most similar repos.
    
    Args:
        source_repo_label: Key in repo_similarity_dict (format: repo-name-commit[:12])
        repo_similarity_dict: Dictionary mapping repo labels to similarity lists
        all_profiles: Dictionary of all loaded software profiles
        text_retriever: EmbeddingRetriever for computing similarities
        top_k: Number of top similar repos to compare with
        module_similarity_threshold: Threshold for module similarity
    
    Returns:
        Dictionary containing comparison results for each similar repo
    """
    from typing import List, Dict, Tuple
    
    # Get source repo info
    # Format: repo-name-commit[:12], commit is always 12 chars
    source_commit = source_repo_label[-12:]
    source_repo_name = source_repo_label[:-13]  # Remove '-commit' (13 chars)
    source_profile = all_profiles[source_repo_name][source_commit]
    
    # Get top-k similar repos
    similar_repos = repo_similarity_dict[source_repo_label][:top_k]
    
    
    print(f"\nTop {top_k} Similar Repositories:")
    for idx, (repo_label, desc_sim, apps_sim, users_sim) in enumerate(similar_repos, 1):
        avg_sim = (desc_sim + apps_sim + users_sim) / 3
        print(f"{idx}. {repo_label} (avg similarity: {avg_sim:.4f})")
    
    # Helper function to create module text representation
    def create_module_text(module: ModuleInfo) -> str:
        parts = [
            f"Module: {module.name}",
            f"Category: {module.category}",
            f"Description: {module.description}",
        ]
        if module.public_apis:
            parts.append(f"APIs: {', '.join(module.public_apis[:5])}")
        if module.external_dependencies:
            parts.append(f"Dependencies: {', '.join(module.external_dependencies[:5])}")
        if module.data_formats:
            parts.append(f"Data formats: {', '.join(module.data_formats)}")
        return " | ".join(parts)
    
    # Get source modules and embeddings
    source_modules = [m for m in source_profile.modules if isinstance(m, ModuleInfo)]
    print(f"\nGenerating embeddings for {len(source_modules)} source modules...")
    source_texts = [create_module_text(m) for m in source_modules]
    source_embeddings = text_retriever.embed(source_texts)
    
    # Compare with each similar repo
    all_results = {}
    
    for rank, (target_repo_label, desc_sim, apps_sim, users_sim, jaccard_sim) in enumerate(similar_repos, 1):
        # Format: repo-name-commit[:12], commit is always 12 chars
        target_commit = target_repo_label[-12:]
        target_repo_name = target_repo_label[:-13]  # Remove '-commit' (13 chars)
        target_profile = all_profiles[target_repo_name][target_commit]
        
        print(f"\n{'='*100}")
        print(f"COMPARING WITH RANK {rank}: {target_repo_label}")
        print(f"{'='*100}")
        
        target_modules = [m for m in target_profile.modules if isinstance(m, ModuleInfo)]
        print(f"Target modules: {len(target_modules)}")
        
        if not target_modules:
            print("No modules to compare!")
            continue
        
        target_texts = [create_module_text(m) for m in target_modules]
        target_embeddings = text_retriever.embed(target_texts)
        
        # Find similar module pairs
        similar_pairs = []
        for i, (source_mod, source_emb) in enumerate(zip(source_modules, source_embeddings)):
            best_match = None
            best_score = module_similarity_threshold
            
            for j, (target_mod, target_emb) in enumerate(zip(target_modules, target_embeddings)):
                similarity = sum(a * b for a, b in zip(source_emb, target_emb))
                
                if similarity > best_score:
                    best_score = similarity
                    best_match = (j, target_mod)
            
            if best_match is not None:
                similar_pairs.append({
                    'source_idx': i,
                    'source_module': source_mod,
                    'target_idx': best_match[0],
                    'target_module': best_match[1],
                    'similarity': best_score
                })
        
        # Sort by similarity
        similar_pairs.sort(key=lambda x: x['similarity'], reverse=True)
        
        print(f"\nFound {len(similar_pairs)} similar module pairs (threshold={module_similarity_threshold})")
        print("\nTop 10 similar module pairs:")
        print("-"*100)
        for i, pair in enumerate(similar_pairs[:10], 1):
            print(f"\n{i}. Similarity: {pair['similarity']:.4f}")
            print(f"   Source [{source_repo_name}]: {pair['source_module'].name}")
            print(f"      Category: {pair['source_module'].category}")
            print(f"   Target [{target_repo_name}]: {pair['target_module'].name}")
            print(f"      Category: {pair['target_module'].category}")
        
        all_results[target_repo_label] = {
            'repo_info': {
                'name': target_repo_name,
                'commit': target_commit,
                'version': target_profile.version,
                'repo_similarity': {
                    'desc': desc_sim,
                    'apps': apps_sim,
                    'users': users_sim,
                    'avg': (desc_sim + apps_sim + users_sim) / 3
                }
            },
            'similar_pairs': similar_pairs,
            'num_pairs': len(similar_pairs)
        }
    
    return all_results
