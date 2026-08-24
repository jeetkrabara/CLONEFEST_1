const PATTERNS = {
  apiKey: /\b(sk|pk)_(live|test)_[A-Za-z0-9]{10,}\b|\bapi[-_]?key\s*[:=]\s*\S{10,}\b|\bBearer\s+[A-Za-z0-9._-]{10,}\b/i,
  awsKey: /\bAKIA[0-9A-Z]{16}\b/,
  privateKey: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,
  creditCard: /\b(?:\d[ -]*?){13,16}\b/,
  password: /\b(password|passwd|pwd)\s*[:=]\s*\S+/i,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  jwt: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/
};

export function detectSecretType(plaintext) {
  if (PATTERNS.privateKey.test(plaintext)) return "private_key";
  if (PATTERNS.awsKey.test(plaintext)) return "aws_credentials";
  if (PATTERNS.jwt.test(plaintext)) return "auth_token";
  if (PATTERNS.apiKey.test(plaintext)) return "api_key";
  if (PATTERNS.password.test(plaintext)) return "password";
  if (PATTERNS.creditCard.test(plaintext)) return "financial_data";
  if (PATTERNS.email.test(plaintext)) return "contains_pii";
  return "generic_text";
}

export function computeSecurityScore(plaintext, secretType) {
  let score = 20;
  const highRisk = ["private_key", "aws_credentials", "auth_token", "api_key"];
  const mediumRisk = ["password", "financial_data"];

  if (highRisk.includes(secretType)) score += 50;
  else if (mediumRisk.includes(secretType)) score += 35;
  else if (secretType === "contains_pii") score += 20;

  if (plaintext.length > 500) score += 10;
  if ((plaintext.match(/\n/g) || []).length > 5) score += 5;

  return Math.min(score, 100);
}

export function getRecommendations(secretType, score) {
  const recs = [];
  const highRisk = ["private_key", "aws_credentials", "auth_token", "api_key"];
  const mediumRisk = ["password", "financial_data"];

  if (score >= 70) {
    recs.push("Consider a short expiration time (under 1 hour) given the sensitivity of this content.");
    recs.push("Use burn-after-reading if only one person needs access.");
  }
  if (highRisk.includes(secretType)) {
    recs.push("This looks like a credential — rotate it after sharing, don't rely on link expiry alone.");
  } else if (mediumRisk.includes(secretType)) {
    recs.push("This appears sensitive — password protection and a reasonable expiration are recommended.");
  } else if (score < 40) {
    recs.push("This content doesn't appear highly sensitive, but password protection is still recommended.");
  }

  return recs;
}

export function analyzeContent(plaintext) {
  const secretType = detectSecretType(plaintext);
  const score = computeSecurityScore(plaintext, secretType);
  const recommendations = getRecommendations(secretType, score);
  return { secretType, score, recommendations };
}