// DevPulse - Production Server for Render (Monolithic Deployment)
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();

// ============================================================================
// CONFIGURATION
// ============================================================================

const PORT = process.env.PORT || 5000;
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Generate or use provided encryption key (must be 64 hex chars = 32 bytes)
let ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
  ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
  console.log('⚠️  Generated new encryption key. Add to Render environment:');
  console.log(`ENCRYPTION_KEY=${ENCRYPTION_KEY}\n`);
} else if (ENCRYPTION_KEY.length !== 64) {
  console.error('❌ ERROR: ENCRYPTION_KEY must be exactly 64 hex characters!');
  console.log('Generate a valid key with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

// Validate environment variables
if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
  console.error('\n❌ ERROR: Missing GitHub OAuth credentials!');
  console.error('Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in Render environment\n');
  process.exit(1);
}

// ============================================================================
// CORS CONFIGURATION
// ============================================================================

const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5000'
];

// Add Render URL from env if it exists
if (process.env.RENDER_EXTERNAL_URL) {
  allowedOrigins.push(process.env.RENDER_EXTERNAL_URL);
}

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (same-origin requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`⚠️  CORS blocked request from origin: ${origin}`);
      callback(null, true); // Allow in production for same-domain
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10mb' }));

// ============================================================================
// SERVE STATIC FRONTEND FILES
// ============================================================================

// Serve static files from React build
app.use(express.static(path.join(__dirname, 'client/build')));

// ============================================================================
// SECURITY & SESSION MANAGEMENT
// ============================================================================

// In-memory secure token storage (server-side only)
const tokenStore = new Map();

// Encryption helpers
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Generate secure session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Middleware: Get access token from session
function getAccessToken(sessionId) {
  const session = tokenStore.get(sessionId);
  if (!session) {
    throw new Error('Invalid or expired session');
  }
  if (session.expiresAt < Date.now()) {
    tokenStore.delete(sessionId);
    throw new Error('Session expired');
  }
  return decrypt(session.accessToken);
}

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

app.post('/api/auth/github', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ success: false, error: 'OAuth code required' });
    }
    
    console.log('📝 Received OAuth code, exchanging for token...');
    
    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code
      })
    });

    const tokenData = await tokenResponse.json();
    
    if (tokenData.error) {
      console.error('❌ GitHub token exchange failed:', tokenData.error_description);
      return res.status(400).json({ 
        success: false, 
        error: tokenData.error_description || 'GitHub auth failed' 
      });
    }

    console.log('✓ Token received, fetching user data...');

    // Get user info
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `token ${tokenData.access_token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'DevPulse-App'
      }
    });

    if (!userResponse.ok) {
      console.error('❌ Failed to fetch user data:', userResponse.status);
      return res.status(401).json({ 
        success: false, 
        error: 'Failed to fetch user information from GitHub' 
      });
    }

    const userData = await userResponse.json();

    // Generate secure session ID
    const sessionId = generateSessionId();
    
    // Store encrypted token server-side
    tokenStore.set(sessionId, {
      accessToken: encrypt(tokenData.access_token),
      userId: userData.id,
      login: userData.login,
      expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
    });

    console.log(`✓ User authenticated: ${userData.login} (Session: ${sessionId.substring(0, 8)}...)`);

    res.json({
      success: true,
      sessionId,
      user: {
        id: userData.id,
        login: userData.login,
        name: userData.name,
        avatar: userData.avatar_url,
        email: userData.email
      }
    });
  } catch (error) {
    console.error('❌ Auth error:', error.message);
    res.status(500).json({ 
      success: false,
      error: 'Authentication failed. Please try again.' 
    });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const { sessionId } = req.body;
  if (sessionId && tokenStore.has(sessionId)) {
    const session = tokenStore.get(sessionId);
    console.log(`✓ User logged out: ${session.login}`);
    tokenStore.delete(sessionId);
  }
  res.json({ success: true });
});

// ============================================================================
// REPOSITORY ROUTES
// ============================================================================

app.post('/api/repo/check-access', async (req, res) => {
  try {
    const { owner, repo, sessionId, username } = req.body;
    const accessToken = getAccessToken(sessionId);

    // Check repository
    const repoResponse = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: {
        'Authorization': `token ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'DevPulse-App'
      }
    });

    if (repoResponse.status === 404) {
      return res.json({ 
        hasAccess: false, 
        isAdmin: false, 
        message: 'Repository not found or no access' 
      });
    }

    if (!repoResponse.ok) {
      throw new Error(`GitHub API error: ${repoResponse.status}`);
    }

    const repoData = await repoResponse.json();

    // Check user permissions
    const permResponse = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/collaborators/${username}/permission`,
      {
        headers: {
          'Authorization': `token ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'DevPulse-App'
        }
      }
    );

    const permData = await permResponse.json();
    const isAdmin = ['admin', 'maintain', 'write'].includes(permData.permission);

    console.log(`✓ Access check: ${owner}/${repo} - ${username} (${permData.permission})`);

    res.json({
      hasAccess: true,
      isAdmin,
      permission: permData.permission,
      repository: {
        name: repoData.name,
        fullName: repoData.full_name,
        private: repoData.private,
        description: repoData.description,
        url: repoData.html_url
      }
    });
  } catch (error) {
    console.error('❌ Repo access check error:', error.message);
    res.status(401).json({ error: error.message });
  }
});

// ============================================================================
// STORAGE ROUTES (GitHub Gists)
// ============================================================================

app.post('/api/storage/save', async (req, res) => {
  try {
    const { sessionId, repoFullName, data, dataType } = req.body;
    const accessToken = getAccessToken(sessionId);
    const session = tokenStore.get(sessionId);

    // Encrypt sensitive data
    const encryptedData = encrypt(JSON.stringify(data));

    const gistFilename = `devpulse_${repoFullName.replace('/', '_')}_${dataType}.json`;
    
    // Check if gist exists
    const gistsResponse = await fetch('https://api.github.com/gists', {
      headers: {
        'Authorization': `token ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'DevPulse-App'
      }
    });

    const gists = await gistsResponse.json();
    const existingGist = gists.find(g => g.files[gistFilename]);

    const gistData = {
      description: `DevPulse data for ${repoFullName} (${dataType})`,
      public: false,
      files: {
        [gistFilename]: {
          content: JSON.stringify({
            encrypted: true,
            repository: repoFullName,
            dataType,
            updatedAt: new Date().toISOString(),
            updatedBy: session.login,
            data: encryptedData
          }, null, 2)
        }
      }
    };

    let result;
    if (existingGist) {
      // Update existing gist
      const updateResponse = await fetch(`https://api.github.com/gists/${existingGist.id}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `token ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json',
          'User-Agent': 'DevPulse-App'
        },
        body: JSON.stringify(gistData)
      });
      result = await updateResponse.json();
      console.log(`✓ Updated gist for ${repoFullName} (${dataType})`);
    } else {
      // Create new gist
      const createResponse = await fetch('https://api.github.com/gists', {
        method: 'POST',
        headers: {
          'Authorization': `token ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json',
          'User-Agent': 'DevPulse-App'
        },
        body: JSON.stringify(gistData)
      });
      result = await createResponse.json();
      console.log(`✓ Created gist for ${repoFullName} (${dataType})`);
    }

    res.json({
      success: true,
      gistId: result.id,
      url: result.html_url
    });

  } catch (error) {
    console.error('❌ Storage save error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/storage/load', async (req, res) => {
  try {
    const { sessionId, repoFullName, dataType } = req.body;
    const accessToken = getAccessToken(sessionId);

    const gistFilename = `devpulse_${repoFullName.replace('/', '_')}_${dataType}.json`;

    // Get all gists
    const gistsResponse = await fetch('https://api.github.com/gists', {
      headers: {
        'Authorization': `token ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'DevPulse-App'
      }
    });

    const gists = await gistsResponse.json();
    const targetGist = gists.find(g => g.files[gistFilename]);

    if (!targetGist) {
      return res.json({ 
        success: true, 
        data: null, 
        message: 'No data found' 
      });
    }

    // Get gist content
    const gistResponse = await fetch(`https://api.github.com/gists/${targetGist.id}`, {
      headers: {
        'Authorization': `token ${accessToken}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'DevPulse-App'
      }
    });

    const gistData = await gistResponse.json();
    const fileContent = JSON.parse(gistData.files[gistFilename].content);

    // Decrypt data
    const decryptedData = JSON.parse(decrypt(fileContent.data));

    console.log(`✓ Loaded gist for ${repoFullName} (${dataType})`);

    res.json({
      success: true,
      data: decryptedData,
      metadata: {
        updatedAt: fileContent.updatedAt,
        updatedBy: fileContent.updatedBy,
        gistUrl: gistData.html_url
      }
    });

  } catch (error) {
    console.error('❌ Storage load error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// ANALYSIS ROUTE
// ============================================================================

app.post('/api/analyze', async (req, res) => {
  try {
    const { repoUrl, objectives, apiKey, sessionId, tasks } = req.body;

    if (!sessionId) {
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication required' 
      });
    }

    if (!apiKey) {
      return res.status(400).json({ 
        success: false,
        error: 'Groq API key required' 
      });
    }

    // Parse repository URL
    const urlPattern = /github\.com\/([^\/]+)\/([^\/\?#]+)/;
    const match = repoUrl.match(urlPattern);
    if (!match) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid GitHub URL' 
      });
    }

    const [, owner, repoName] = match;
    const cleanRepo = repoName.replace(/\.git$/, '');
    const session = tokenStore.get(sessionId);
    const accessToken = getAccessToken(sessionId);

    console.log(`\n🔍 Analyzing ${owner}/${cleanRepo} (User: ${session.login})...`);

    // Fetch GitHub data
    const headers = {
      'Authorization': `token ${accessToken}`,
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'DevPulse-App'
    };

    const [repoData, contributors, commits, languages] = await Promise.all([
      fetch(`https://api.github.com/repos/${owner}/${cleanRepo}`, { headers }).then(r => r.json()),
      fetch(`https://api.github.com/repos/${owner}/${cleanRepo}/contributors?per_page=15`, { headers }).then(r => r.json()),
      fetch(`https://api.github.com/repos/${owner}/${cleanRepo}/commits?per_page=100`, { headers }).then(r => r.json()),
      fetch(`https://api.github.com/repos/${owner}/${cleanRepo}/languages`, { headers }).then(r => r.json())
    ]);

    console.log('✓ GitHub data fetched');
    console.log('🚀 Analyzing with Groq AI...');

    // AI Analysis
    const aiAnalysis = await analyzeWithGroq(
      repoData, 
      contributors, 
      commits, 
      objectives, 
      tasks || [],
      apiKey
    );

    console.log('✓ Analysis complete!\n');

    res.json({
      success: true,
      repository: {
        name: repoData.name,
        fullName: repoData.full_name,
        description: repoData.description,
        language: repoData.language,
        private: repoData.private,
        stars: repoData.stargazers_count,
        forks: repoData.forks_count,
        openIssues: repoData.open_issues_count,
        watchers: repoData.watchers_count,
        url: repoData.html_url,
        languages
      },
      contributors: contributors.map(c => ({
        login: c.login,
        contributions: c.contributions,
        avatar: c.avatar_url,
        url: c.html_url
      })),
      commits: commits.map(c => ({
        message: c.commit.message,
        author: c.commit.author.name,
        authorLogin: c.author?.login || c.commit.author.name,
        date: c.commit.author.date,
        sha: c.sha,
        url: c.html_url
      })),
      analysis: aiAnalysis,
      metadata: {
        analyzedAt: new Date().toISOString(),
        analyzedBy: session.login,
        objectives: objectives || null,
        aiModel: 'Llama 3.3 70B (Groq)',
        tasksAnalyzed: tasks?.length || 0
      }
    });

  } catch (error) {
    console.error('❌ Analysis error:', error.message);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============================================================================
// AI ANALYSIS FUNCTION
// ============================================================================

async function analyzeWithGroq(repoData, contributors, commits, objectives, tasks, apiKey) {
  let taskContext = '';
  
  if (tasks && tasks.length > 0) {
    taskContext = `\n\nASSIGNED TASKS (Compare commits against these):
${tasks.map((t, i) => `
Task ${i + 1}: ${t.title}
Description: ${t.description}
Assigned to: ${t.assignedTo?.join(', ') || 'Unassigned'}
Expected outcomes: ${t.expectedOutcomes?.join(', ') || 'Not specified'}
Priority: ${t.priority}
Status: ${t.status}
`).join('\n')}

For each contributor assigned to tasks, analyze their commits and provide:
1. Task alignment score (0-10)
2. Code quality score (0-10)
3. Timeliness score (0-10)
4. Efficiency score (0-10)
5. Detailed analysis of how commits match task requirements`;
  }

  const prompt = `Analyze this GitHub repository and provide detailed performance insights.

Repository: ${repoData.name}
Description: ${repoData.description || 'No description'}
Language: ${repoData.language || 'Multiple'}
Stars: ${repoData.stargazers_count}
Objectives: ${objectives || 'General analysis'}
${taskContext}

Contributors (Top 10):
${contributors.slice(0, 10).map((c, i) => `${i + 1}. ${c.login} - ${c.contributions} commits`).join('\n')}

Recent Commits (Last 30):
${commits.slice(0, 30).map((c, i) => {
  const msg = c.commit.message.split('\n')[0].substring(0, 100);
  const author = c.author?.login || c.commit.author.name;
  return `${i + 1}. [${author}] "${msg}"`;
}).join('\n')}

Return ONLY valid JSON (no markdown, no code blocks):
{
  "contributors": [
    {
      "name": "username",
      "overallScore": "8.5/10",
      "impact": "detailed analysis of their contributions",
      "strengths": ["strength1", "strength2", "strength3"],
      "areasForImprovement": ["area1", "area2"],
      "taskPerformance": {
        "taskAlignmentScore": "9/10",
        "codeQualityScore": "8.5/10",
        "timelinessScore": "7.5/10",
        "efficiencyScore": "8.8/10",
        "taskSpecificAnalysis": "detailed analysis of task completion"
      }
    }
  ],
  "codeHealth": {
    "score": "8.5/10",
    "insights": "overall code health assessment",
    "metrics": {
      "commitFrequency": "high/medium/low with explanation",
      "codeQuality": "excellent/good/needs improvement with explanation",
      "collaboration": "excellent/good/needs improvement with explanation"
    }
  },
  "recommendations": [
    "specific actionable recommendation 1",
    "specific actionable recommendation 2",
    "specific actionable recommendation 3"
  ]
}`;

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { 
          role: 'system', 
          content: 'You are an expert software engineering analyst. Return ONLY valid JSON, no markdown, no code blocks, no extra text.' 
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0.7,
      max_tokens: 4096
    })
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || 'Groq API error');
  }

  const data = await response.json();
  const text = data.choices[0].message.content;
  
  // Extract JSON from response (handle markdown code blocks)
  let jsonText = text;
  const jsonMatch = text.match(/```json\s*\n?([\s\S]*?)\n?```/) || text.match(/```\s*\n?([\s\S]*?)\n?```/);
  if (jsonMatch) {
    jsonText = jsonMatch[1];
  }
  
  // Try to parse
  try {
    return JSON.parse(jsonText);
  } catch (e) {
    // If still fails, try to extract just the JSON object
    const objectMatch = jsonText.match(/\{[\s\S]*\}/);
    if (objectMatch) {
      return JSON.parse(objectMatch[0]);
    }
    throw new Error('Invalid AI response format');
  }
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'DevPulse Backend',
    version: '2.0.0',
    platform: 'Render',
    model: 'Llama 3.3 70B (Groq)',
    features: [
      'GitHub OAuth',
      'Private Repositories',
      'Task Management (GitHub Gists)',
      'Encrypted Token Storage',
      'Multi-Repository Support',
      'AI Performance Analysis'
    ],
    security: {
      tokenStorage: 'Server-side AES-256 encrypted',
      dataStorage: 'GitHub Gists (encrypted)',
      sessions: tokenStore.size
    }
  });
});

// ============================================================================
// FRONTEND ROUTING - MUST BE LAST
// ============================================================================

// All other routes serve the React app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

// ============================================================================
// CLEANUP & SERVER START
// ============================================================================

// Cleanup expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [id, data] of tokenStore.entries()) {
    if (data.expiresAt < now) {
      tokenStore.delete(id);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`🧹 Cleaned ${cleaned} expired sessions`);
  }
}, 5 * 60 * 1000);

// Start server
app.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║          🚀 DevPulse - Render Deployment                 ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');
  console.log(`📡 Server:        Port ${PORT}`);
  console.log(`🌐 Platform:      Render`);
  console.log(`🔐 GitHub OAuth:  ${GITHUB_CLIENT_ID ? '✓ Configured' : '❌ Not configured'}`);
  console.log(`🔑 Encryption:    ${ENCRYPTION_KEY ? '✓ Enabled (AES-256)' : '❌ Disabled'}`);
  console.log(`🤖 AI Model:      Llama 3.3 70B (Groq)`);
  console.log(`\n🛡️  Security Features:`);
  console.log(`   ✓ Server-side encrypted token storage`);
  console.log(`   ✓ GitHub Gists for data persistence`);
  console.log(`   ✓ Session-based authentication (24h expiry)`);
  console.log(`   ✓ CORS protection`);
  console.log(`   ✓ Automatic session cleanup`);
  console.log(`\n✅ Ready to accept connections!\n`);
});

// Error handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

module.exports = app;