import joblib
import validators
from url_features import extract_features, features_to_vector, FEATURE_ORDER

class PhishingDetector:
    def __init__(self, model_path="phishing_model.pkl"):
        self.model = joblib.load(model_path)

    def _rule_score(self, f: dict) -> tuple[int, list]:
        """Return (score 0-100, reasons)."""
        score = 0
        reasons = []

        if f['has_ip_host']:
            score += 30; reasons.append("URL uses raw IP address")
        if f['has_at_symbol']:
            score += 20; reasons.append("Contains '@' (URL obfuscation)")
        if f['has_double_slash_redirect']:
            score += 15; reasons.append("Double-slash redirect in path")
        if f['suspicious_tld']:
            score += 20; reasons.append("Suspicious TLD (e.g., .tk, .xyz, .top)")
        if f['uses_shortener']:
            score += 15; reasons.append("URL shortener hides destination")
        if f['brand_in_subdomain']:
            score += 25; reasons.append("Brand name in subdomain (impersonation)")
        if f['suspicious_word_count'] >= 3:
            score += 15; reasons.append(f"{f['suspicious_word_count']} suspicious keywords")
        if f['url_length'] > 75:
            score += 10; reasons.append("Unusually long URL")
        if f['num_hyphens'] >= 3:
            score += 10; reasons.append("Excessive hyphens in domain")
        if f['entropy'] > 4.0:
            score += 10; reasons.append("High hostname entropy (random-looking)")
        if not f['is_https']:
            score += 5; reasons.append("Not using HTTPS")
        if f['num_subdomains'] >= 3:
            score += 10; reasons.append("Deeply nested subdomains")

        return min(score, 100), reasons

    def predict(self, url: str) -> dict:
        if not validators.url(url) and not validators.domain(url):
            return {"url": url, "error": "Invalid URL"}

        feats = extract_features(url)
        vec = [features_to_vector(feats)]

        ml_prob = float(self.model.predict_proba(vec)[0][1])  # P(phishing)

        rule_score, reasons = self._rule_score(feats)

        # Weighted combination
        final_score = 0.65 * ml_prob * 100 + 0.35 * rule_score

        verdict = "PHISHING" if final_score >= 50 else "SAFE"
        risk = "HIGH" if final_score >= 70 else "MEDIUM" if final_score >= 40 else "LOW"

        return {
            "url": url,
            "verdict": verdict,
            "risk": risk,
            "score": round(final_score, 2),
            "ml_probability": round(ml_prob, 4),
            "rule_score": rule_score,
            "reasons": reasons,
            "features": feats,
        }


if __name__ == "__main__":
    detector = PhishingDetector("phishing_model.pkl")

    tests = [
        "https://www.google.com",
        "http://paypal.com.secure-login-verify.xyz/account/update",
        "http://192.168.0.1/login.php",
        "https://github.com/python/cpython",
        "http://free-iphone-winner.tk/claim",
    ]

    for t in tests:
        r = detector.predict(t)
        print(f"\n{r['url']}")
        print(f"  Verdict: {r['verdict']} | Risk: {r['risk']} | Score: {r['score']}")
        if r['reasons']:
            for reason in r['reasons']:
                print(f"    ⚠ {reason}")