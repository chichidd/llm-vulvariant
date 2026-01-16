from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ai_infra_taxonomy import AI_INFRA_TAXONOMY

# Simple rule-based classifier: converts scan_repo.py output into candidate module
# labels with confidence and evidence. The agent should review and refine.

# Map scan keyword groups to taxonomy top-level keys
GROUP_TO_TOP = {
    'training': 'training',
    'inference_and_serving': 'inference_and_serving',
    'app_and_orchestration': 'app_and_orchestration',
    'data': 'data',
    'evaluation_and_safety': 'evaluation_and_safety',
    'ops_and_governance': 'ops_and_governance',
}

def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def classify(scan: Dict[str, Any]) -> Dict[str, Any]:
    kw = scan.get('keyword_counts', {})
    # Convert keyword hit counts into a bounded confidence.
    modules: List[Dict[str, Any]] = []
    for group, top in GROUP_TO_TOP.items():
        c = int(kw.get(group, 0))
        # Saturating confidence: ~0.5 at 2 hits, ~0.88 at 6 hits
        conf = _sigmoid(0.6 * (c - 2))
        if c > 0:
            modules.append({
                'label': top,
                'confidence': round(float(conf), 3),
                'evidence': [f"keyword_group:{group} hits={c}"],
            })

    # Directory-based weak signals
    dirs = set(scan.get('top_dirs', []))
    dir_hints = {
        'scripts': 'foundation',
        'docker': 'ops_and_governance',
        'deploy': 'ops_and_governance',
        'k8s': 'ops_and_governance',
        'helm': 'ops_and_governance',
        'examples': 'app_and_orchestration',
        'notebooks': 'evaluation_and_safety',
    }
    for d, top in dir_hints.items():
        if d in dirs:
            modules.append({
                'label': top,
                'confidence': 0.55,
                'evidence': [f"dir_hint:{d}"],
            })

    # Merge by label (max confidence, aggregate evidence)
    merged: Dict[str, Dict[str, Any]] = {}
    for m in modules:
        lab = m['label']
        if lab not in merged:
            merged[lab] = {'label': lab, 'confidence': m['confidence'], 'evidence': list(m['evidence'])}
        else:
            merged[lab]['confidence'] = max(merged[lab]['confidence'], m['confidence'])
            merged[lab]['evidence'].extend(m['evidence'])

    out = {
        'repo': scan.get('repo_name'),
        'path': scan.get('repo_path'),
        'languages': scan.get('languages', {}),
        'modules': sorted(merged.values(), key=lambda x: (-x['confidence'], x['label']))
    }
    return out


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument('scan_json', type=Path)
    ap.add_argument('-o', '--out', type=Path, default=None)
    args = ap.parse_args()

    scan = json.loads(args.scan_json.read_text(encoding='utf-8'))
    result = classify(scan)
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(text, encoding='utf-8')
    else:
        print(text)


if __name__ == '__main__':
    main()
