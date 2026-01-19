// DevTrack AI - Using FREE Groq API (Faster & More Reliable!)
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch'); // ADD THIS LINE
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

async function fetchGitHub(url) {
  try {
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'DevTrack-AI'
      },
      timeout: 10000 // 10 second timeout
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`GitHub API error: ${response.status} - ${errorText}`);
    }
    
    return response.json();
  } catch (error) {
    if (error.type === 'request-timeout') {
      throw new Error('GitHub API timeout - please try again');
    }
    throw error;
  }
}

// Groq API - FREE and SUPER FAST!
async function analyzeWithGroq(repoData, contributors, commits, objectives, apiKey) {
  const prompt = `Analyze this GitHub repository and provide detailed insights.

Repository: ${repoData.name}
Description: ${repoData.description || 'No description'}
Language: ${repoData.language || 'Multiple'}
Stars: ${repoData.stargazers_count}
Objectives: ${objectives || 'General analysis'}

Top Contributors:
${contributors.slice(0, 5).map((c, i) => `${i + 1}. ${c.login} - ${c.contributions} commits`).join('\n')}

Recent Commits:
${commits.slice(0, 15).map((c, i) => `${i + 1}. "${c.commit.message.split('\n')[0]}"`).join('\n')}

Return ONLY valid JSON:
{
  "contributors": [{"name": "username", "impact": "detailed analysis", "score": 85, "strengths": ["s1", "s2"], "focus": "area"}],
  "alignment": {"score": 80, "analysis": "detailed text", "keyAchievements": ["a1", "a2"]},
  "codeHealth": {"score": 85, "insights": "detailed text", "metrics": {"commitFrequency": "high", "codeQuality": "good", "testCoverage": "medium"}},
  "recommendations": ["rec1", "rec2", "rec3", "rec4"],
  "teamDynamics": {"collaborationScore": 85, "insights": "detailed text"}
}`;

  try {
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
            content: 'You are an expert software engineering analyst. Always return valid JSON only, no markdown or code blocks.' 
          },
          { role: 'user', content: prompt }
        ],
        temperature: 0.7,
        max_tokens: 4096
      }),
      timeout: 30000 // 30 second timeout
    });

    if (!response.ok) {
      const error = await response.json();
      console.error('Groq Error:', error);
      throw new Error(error.error?.message || 'Groq API error - check your API key');
    }

    const data = await response.json();
    const text = data.choices[0].message.content;
    
    // Extract JSON
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('Invalid AI response');
    
    return JSON.parse(jsonMatch[0]);
  } catch (error) {
    if (error.type === 'request-timeout') {
      throw new Error('Groq API timeout - please try again');
    }
    throw error;
  }
}

app.post('/api/analyze', async (req, res) => {
  try {
    const { repoUrl, objectives, apiKey } = req.body;

    if (!repoUrl) {
      return res.status(400).json({ error: 'Repository URL required' });
    }

    if (!apiKey) {
      return res.status(400).json({ 
        error: 'API key required. Get FREE Groq key (takes 30 seconds): https://console.groq.com/keys' 
      });
    }

    const urlPattern = /github\.com\/([^\/]+)\/([^\/\?#]+)/;
    const match = repoUrl.match(urlPattern);
    if (!match) {
      return res.status(400).json({ error: 'Invalid GitHub URL' });
    }

    const [, owner, repoName] = match;
    const cleanRepo = repoName.replace(/\.git$/, '');

    console.log(`\n🔍 Analyzing ${owner}/${cleanRepo}...`);

    const [repoData, contributors, commits, languages] = await Promise.all([
      fetchGitHub(`https://api.github.com/repos/${owner}/${cleanRepo}`),
      fetchGitHub(`https://api.github.com/repos/${owner}/${cleanRepo}/contributors?per_page=10`),
      fetchGitHub(`https://api.github.com/repos/${owner}/${cleanRepo}/commits?per_page=100`),
      fetchGitHub(`https://api.github.com/repos/${owner}/${cleanRepo}/languages`)
    ]);

    console.log('✓ GitHub data fetched');
    console.log('🚀 Analyzing with Groq (Llama 3.3)...');

    const aiAnalysis = await analyzeWithGroq(repoData, contributors, commits, objectives, apiKey);

    console.log('✓ Complete!\n');

    res.json({
      success: true,
      repository: {
        name: repoData.name,
        fullName: repoData.full_name,
        description: repoData.description,
        language: repoData.language,
        stars: repoData.stargazers_count,
        forks: repoData.forks_count,
        openIssues: repoData.open_issues_count,
        watchers: repoData.watchers_count,
        url: repoData.html_url,
        languages: languages
      },
      contributors: contributors.slice(0, 10).map(c => ({
        login: c.login,
        contributions: c.contributions,
        avatar: c.avatar_url,
        url: c.html_url
      })),
      commits: commits.slice(0, 50).map(c => ({
        message: c.commit.message,
        author: c.commit.author.name,
        date: c.commit.author.date,
        sha: c.sha.substring(0, 7),
        url: c.html_url
      })),
      analysis: aiAnalysis,
      metadata: {
        analyzedAt: new Date().toISOString(),
        objectives: objectives || null,
        aiModel: 'Llama 3.3 70B (Groq)'
      }
    });

  } catch (error) {
    console.error('❌ Error:', error.message);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    service: 'DevTrack AI - Groq',
    model: 'Llama 3.3 70B' 
  });
});

app.listen(PORT, () => {
  console.log('\n🚀 DevTrack AI - Groq Edition (FREE)');
  console.log(`📡 Server: http://localhost:${PORT}`);
  console.log(`🤖 Model: Llama 3.3 70B (via Groq)`);
  console.log(`🔑 Get FREE API key: https://console.groq.com/keys`);
  console.log(`⚡ Fastest inference in the world!\n`);
});

module.exports = app;