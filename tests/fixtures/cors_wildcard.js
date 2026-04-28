// Fixture: Lead Gen CORS wildcard
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({ origin: '*' }));

app.get('/api/leads', (req, res) => {
  res.json({ leads: [] });
});
