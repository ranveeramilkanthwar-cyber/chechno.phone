"""
PrivaIndia Runtime DOM & Selector Self-Healing Engine
Tier 1 Closed-Loop Shadow DOM Heuristic Resolver for Indian Directory Portals.
"""
import difflib
from typing import Dict, List, Optional, Any

SEMANTIC_ERASURE_KEYWORDS = [
    "opt out", "remove my number", "unlist", "delete data", "erase",
    "dpdp", "grievance", "privacy request", "unsubscribe", "do not call",
    "request removal", "delete profile", "withdraw consent"
]

def score_dom_element(cand: Dict[str, Any], failed_selector: str) -> float:
    """
    Scores candidate interactive element in DOM against semantic anchors
    and textual/selector similarity.
    """
    if not cand.get("visible", True):
        return 0.0
    text_content = cand.get("text", "")
    aria_label = cand.get("ariaLabel", "")
    elem_id = cand.get("id", "")
    test_id = cand.get("testId", "")
    
    blob = f"{text_content} {aria_label} {elem_id} {test_id}".lower()
    keyword_hits = sum(1 for kw in SEMANTIC_ERASURE_KEYWORDS if kw in blob)
    seq_ratio = difflib.SequenceMatcher(None, failed_selector.lower(), blob).ratio()
    
    # Weight keywords (45%) and string sequence similarity (55%)
    score = (keyword_hits * 0.45) + (seq_ratio * 0.55)
    return score

def resolve_best_selector(candidates: List[Dict[str, Any]], failed_selector: str) -> Optional[str]:
    """
    Selects best synthesized selector from candidate DOM elements.
    """
    best_score = 0.0
    best_selector: Optional[str] = None
    
    for cand in candidates:
        score = score_dom_element(cand, failed_selector)
        if score > best_score:
            best_score = score
            tag = cand.get("tag", "button")
            if cand.get("testId"):
                best_selector = f"{tag}[data-testid='{cand['testId']}']"
            elif cand.get("id"):
                best_selector = f"#{cand['id']}"
            elif cand.get("text"):
                safe_text = cand["text"].replace("'", "").strip()
                best_selector = f"//{tag}[contains(normalize-space(.), '{safe_text}')]"
                
    if best_selector and best_score >= 0.35:
        return best_selector
    return None
