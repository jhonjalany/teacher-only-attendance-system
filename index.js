const express = require('express');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
app.use(express.json());

const GOOGLE_JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs'; 
const CLIENT_ID = process.env.CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID_HERE';

app.post('/verify-google-token', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ success: false, message: 'Token is required' });
  }

  try {
    // Fetch public keys
    const jwksRes = await axios.get(GOOGLE_JWKS_URI);
    const jwks = jwksRes.data.keys;

    // Decode header to get key ID
    const decodedHeader = jwt.decode(token, { complete: true });
    const signingKey = jwks.find(key => key.kid === decodedHeader.header.kid);

    if (!signingKey) throw new Error('Signing key not found');

    // Convert JWK to PEM format
    const publicKey = jwt.certToPEM(JSON.stringify(signingKey));

    // Verify token
    const payload = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: ['accounts.google.com', 'https://accounts.google.com'], 
      audience: CLIENT_ID
    });

    return res.json({ success: true, payload });
  } catch (error) {
    return res.status(401).json({ success: false, message: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));