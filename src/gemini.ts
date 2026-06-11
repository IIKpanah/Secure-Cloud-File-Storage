import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "");

export const analyzeSystemSecurity = async (logs: any[], metrics: any[]) => {
  const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

  const prompt = `
    You are a Senior Security Auditor for a Zero-Trust Hybrid Encryption Vault.
    Review the following system data and provide a concise Security Integrity Report.
    
    AUDIT LOGS (Last 20):
    ${JSON.stringify(logs.slice(0, 20), null, 2)}
    
    PERFORMANCE METRICS (Last 20):
    ${JSON.stringify(metrics.slice(0, 20), null, 2)}
    
    Your report must include:
    1. Overall Security Score (0-100).
    2. Threat Detection (Any suspicious patterns like repeated AUTH_FAIL or large bulk uploads).
    3. Performance Health (Are cryptographic operations within safe latency bounds?).
    4. Compliance check: RSA/AES hybrid integrity status.
    
    FORMAT: Respond in clean Markdown.
  `;

  const result = await model.generateContent(prompt);
  return result.response.text();
};
