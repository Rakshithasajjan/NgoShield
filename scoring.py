PENALTY = {"high": 15, "medium": 8, "low": 3}


def score(findings):
    total = 100 - sum(PENALTY.get(f.severity, 0) for f in findings if f.status == "fail")
    total = max(0, total)
    grade = "A" if total >= 90 else "B" if total >= 80 else "C" if total >= 70 else "D" if total >= 55 else "F"
    return total, grade
