import math
from collections import Counter

def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy for a text string. 
    A lower score implies highly patterned/repetitive data (potential synthetic forgery).
    """
    if not text: return 0.0
    p, lns = Counter(text), float(len(text))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())
