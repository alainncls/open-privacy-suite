// Mock Billions identity service for testing
const express = require('express');
const app = express();
const PORT = process.env.PORT || 9000;

app.use(express.json());

// Health check endpoint (no auth required)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Mock identity responses based on token
// Format: token "user_123" -> subject "billions:user_123"
app.get('/verify', (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'missing or invalid Authorization header'
    });
  }
  
  const token = authHeader.substring(7); // Remove "Bearer "
  
  if (!token || token.trim() === '') {
    return res.status(401).json({
      error: 'empty token'
    });
  }
  
  // Mock: Billions service receives user_id (without prefix)
  // Returns subject with "billions:" prefix
  // Token format: "ivan_1" -> subject "billions:ivan_1"
  const subject = `billions:${token}`;
  
  // Mock KYC status (default to true)
  const kyc = true;
  
  // Mock claims
  const claims = {
    token: token,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  
  const identity = {
    subject: subject,
    kyc: kyc,
    claims: claims,
  };
  
  console.log(`[Mock Billions] Verified token: ${token} -> ${subject}`);
  
  res.json(identity);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Mock Billions service listening on port ${PORT}`);
});
