import React, { useState, useEffect } from 'react';
import { LogOut, Plus, Trash2, Edit, X, Target, AlertTriangle, TrendingUp, Loader2, Lock, Clock, RefreshCw, Save, BarChart3, Users, FileText, CheckCircle2, Circle, AlertCircle } from 'lucide-react';

// Configuration - Update these values directly
const CONFIG = {
  API_URL: 'http://localhost:5000',
  GITHUB_CLIENT_ID: 'Ov23linVs5BQek63QtJ4',
  MAX_REPOS: 5
};

const SecureSession = {
  set: (sessionId, user) => {
    sessionStorage.setItem('session', sessionId);
    sessionStorage.setItem('user', JSON.stringify(user));
  },
  getSessionId: () => sessionStorage.getItem('session'),
  getUser: () => {
    const u = sessionStorage.getItem('user');
    return u ? JSON.parse(u) : null;
  },
  clear: () => {
    sessionStorage.clear();
    localStorage.clear();
  }
};

// Custom Professional Logo Component
const DevPulseLogo = ({ size = 40 }) => (
  <svg width={size} height={size} viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" rx="20" fill="url(#gradient)" />
    <defs>
      <linearGradient id="gradient" x1="0" y1="0" x2="100" y2="100" gradientUnits="userSpaceOnUse">
        <stop stopColor="#3B82F6" />
        <stop offset="1" stopColor="#1E40AF" />
      </linearGradient>
    </defs>
    <path d="M30 50 L45 35 L60 50 L75 30" stroke="white" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" fill="none" />
    <circle cx="30" cy="50" r="4" fill="white" />
    <circle cx="45" cy="35" r="4" fill="white" />
    <circle cx="60" cy="50" r="4" fill="white" />
    <circle cx="75" cy="30" r="4" fill="white" />
    <path d="M25 70 L75 70" stroke="white" strokeWidth="3" strokeLinecap="round" />
  </svg>
);

export default function App() {
  const [user, setUser] = useState(SecureSession.getUser());
  const [sessionId, setSessionId] = useState(SecureSession.getSessionId());
  const [groqKey, setGroqKey] = useState(localStorage.getItem('groq') || '');
  const [tempGroqKey, setTempGroqKey] = useState(localStorage.getItem('groq') || '');
  const [repos, setRepos] = useState(JSON.parse(localStorage.getItem('repos') || '[]'));
  const [activeRepo, setActiveRepo] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('repos');
  const [showModal, setShowModal] = useState(false);
  const [editTask, setEditTask] = useState(null);
  const [lastSync, setLastSync] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [newRepoUrl, setNewRepoUrl] = useState('');

  useEffect(() => {
    const code = new URLSearchParams(window.location.search).get('code');
    if (code && !sessionId) {
      console.log('OAuth code detected, attempting authentication...');
      handleAuth(code);
    }
    if (activeRepo && sessionId) loadTasks();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeRepo]);

  const handleAuth = async (code) => {
    setAuthLoading(true);
    setError('');
    try {
      console.log('Sending auth request to:', `${CONFIG.API_URL}/api/auth/github`);
      
      const res = await fetch(`${CONFIG.API_URL}/api/auth/github`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ code })
      });

      console.log('Auth response status:', res.status);
      
      if (!res.ok) {
        const errorText = await res.text();
        console.error('Auth failed:', errorText);
        throw new Error(`Authentication failed: ${res.status} ${res.statusText}`);
      }

      const data = await res.json();
      console.log('Auth response:', data);
      
      if (data.success) {
        setUser(data.user);
        setSessionId(data.sessionId);
        SecureSession.set(data.sessionId, data.user);
        window.history.replaceState({}, '', '/');
        console.log('Authentication successful!');
      } else {
        throw new Error(data.error || 'Authentication failed');
      }
    } catch (e) {
      console.error('Authentication error:', e);
      setError(`Authentication failed: ${e.message}. Please check if the backend is running at ${CONFIG.API_URL}`);
    } finally {
      setAuthLoading(false);
    }
  };

  const login = () => {
    const redirectUri = window.location.origin;
    const url = `https://github.com/login/oauth/authorize?client_id=${CONFIG.GITHUB_CLIENT_ID}&redirect_uri=${redirectUri}&scope=repo,gist,read:user`;
    console.log('Redirecting to GitHub OAuth:', url);
    window.location.href = url;
  };

  const logout = async () => {
    try {
      await fetch(`${CONFIG.API_URL}/api/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId })
      });
    } catch (e) {
      console.error('Logout error:', e);
    }
    setUser(null);
    setSessionId(null);
    setRepos([]);
    setActiveRepo(null);
    setTasks([]);
    setAnalysis(null);
    SecureSession.clear();
  };

  const saveGroqKey = () => {
    localStorage.setItem('groq', tempGroqKey);
    setGroqKey(tempGroqKey);
    setError('');
  };

  const addRepo = async () => {
    if (!newRepoUrl.trim()) {
      return setError('Please enter a repository URL');
    }

    if (repos.length >= CONFIG.MAX_REPOS) {
      return setError(`Maximum ${CONFIG.MAX_REPOS} repositories allowed`);
    }

    const m = newRepoUrl.match(/github\.com\/([^/]+)\/([^/]+)/);
    if (!m) return setError('Invalid GitHub repository URL');
    const [, owner, name] = m;
    const repo = name.replace('.git', '');
    
    // Check if repo already added
    if (repos.some(r => r.fullName === `${owner}/${repo}`)) {
      return setError('Repository already added');
    }

    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${CONFIG.API_URL}/api/repo/check-access`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ owner, repo, sessionId, username: user.login })
      });
      
      if (!res.ok) {
        throw new Error(`Failed to check repository access: ${res.status}`);
      }
      
      const data = await res.json();
      if (!data.hasAccess) return setError('Access denied to this repository');
      const newRepo = { ...data.repository, owner, isAdmin: data.isAdmin };
      const updated = [...repos, newRepo];
      setRepos(updated);
      localStorage.setItem('repos', JSON.stringify(updated));
      setActiveRepo(newRepo);
      setNewRepoUrl('');
      setTab('tasks');
    } catch (e) {
      console.error('Add repo error:', e);
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const removeRepo = (repoToRemove) => {
    const updated = repos.filter(r => r.fullName !== repoToRemove.fullName);
    setRepos(updated);
    localStorage.setItem('repos', JSON.stringify(updated));
    if (activeRepo?.fullName === repoToRemove.fullName) {
      setActiveRepo(null);
      setTasks([]);
      setAnalysis(null);
      setTab('repos');
    }
  };

  const loadTasks = async () => {
    setSyncing(true);
    try {
      const res = await fetch(`${CONFIG.API_URL}/api/storage/load`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId,
          repoFullName: activeRepo.fullName,
          dataType: 'tasks'
        })
      });
      const data = await res.json();
      if (data.success && data.data) {
        setTasks(data.data);
        setLastSync(data.metadata?.updatedAt);
      } else {
        setTasks([]);
      }
    } catch (e) {
      console.error('Load tasks error:', e);
    } finally {
      setSyncing(false);
    }
  };

  const saveTasks = async (updated) => {
    setSyncing(true);
    try {
      await fetch(`${CONFIG.API_URL}/api/storage/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId,
          repoFullName: activeRepo.fullName,
          dataType: 'tasks',
          data: updated
        })
      });
      setTasks(updated);
      setLastSync(new Date().toISOString());
    } catch (e) {
      setError('Synchronization failed. Please try again.');
    } finally {
      setSyncing(false);
    }
  };

  const saveTask = () => {
    if (!editTask?.title) return;
    const task = {
      id: editTask.id || Date.now().toString(),
      ...editTask,
      createdBy: user.login,
      createdAt: editTask.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    const updated = tasks.find(t => t.id === task.id)
      ? tasks.map(t => t.id === task.id ? task : t)
      : [...tasks, task];
    saveTasks(updated);
    setShowModal(false);
    setEditTask(null);
  };

  const deleteTask = (id) => {
    setConfirmDelete(id);
  };

  const confirmDeleteTask = () => {
    if (confirmDelete) {
      saveTasks(tasks.filter(t => t.id !== confirmDelete));
    }
    setConfirmDelete(null);
  };

  const analyze = async () => {
    if (!groqKey) {
      setError('Please enter your Groq API key first');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${CONFIG.API_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl: `https://github.com/${activeRepo.fullName}`,
          objectives: '',
          apiKey: groqKey,
          sessionId,
          tasks
        })
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      setAnalysis(data);
      setTab('results');
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800 border-green-200';
      case 'in-progress': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle2 className="w-4 h-4" />;
      case 'in-progress': return <Circle className="w-4 h-4" />;
      default: return <AlertCircle className="w-4 h-4" />;
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50 flex items-center justify-center p-4">
        <div className="bg-white rounded-3xl shadow-2xl p-12 max-w-md w-full border border-gray-100">
          <div className="flex justify-center mb-6">
            <DevPulseLogo size={80} />
          </div>
          <h1 className="text-4xl font-bold text-center mb-3 text-gray-900">DevPulse</h1>
          <p className="text-gray-600 text-center mb-8 text-lg">Enterprise Performance Analytics</p>
          
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-6">
              <div className="flex gap-3">
                <AlertTriangle className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="font-semibold text-red-900 text-sm">Authentication Error</p>
                  <p className="text-sm text-red-700 mt-0.5">{error}</p>
                </div>
              </div>
            </div>
          )}

          {authLoading && (
            <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6 text-center">
              <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2 text-blue-600" />
              <p className="text-sm text-blue-800 font-medium">Authenticating with GitHub...</p>
            </div>
          )}
          
          <div className="space-y-4 mb-8 bg-gray-50 rounded-xl p-6 border border-gray-200">
            <div className="flex items-start gap-3">
              <Lock className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-semibold text-gray-900 text-sm">Secure Data Encryption</p>
                <p className="text-gray-600 text-xs mt-0.5">End-to-end encrypted storage</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Users className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-semibold text-gray-900 text-sm">Team Collaboration</p>
                <p className="text-gray-600 text-xs mt-0.5">Shared via GitHub Gists</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <BarChart3 className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-semibold text-gray-900 text-sm">AI-Powered Insights</p>
                <p className="text-gray-600 text-xs mt-0.5">Advanced performance analytics</p>
              </div>
            </div>
          </div>

          <button 
            onClick={login} 
            disabled={authLoading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 disabled:cursor-not-allowed transition-colors py-4 rounded-xl font-semibold text-white shadow-lg hover:shadow-xl flex items-center justify-center gap-2"
          >
            {authLoading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Connecting...
              </>
            ) : (
              'Sign in with GitHub'
            )}
          </button>
          
          <p className="text-center text-xs text-gray-500 mt-6">
            Secure authentication via GitHub OAuth
          </p>
          
          <div className="mt-6 pt-6 border-t border-gray-200">
            <p className="text-xs text-gray-500 text-center mb-2">Backend API:</p>
            <p className="text-xs font-mono text-gray-700 text-center bg-gray-100 py-2 px-3 rounded-lg">
              {CONFIG.API_URL}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50 shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-4">
              <DevPulseLogo size={40} />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">DevPulse</h1>
                <p className="text-xs text-gray-500">Performance Analytics Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right mr-2 hidden sm:block">
                <p className="text-sm font-semibold text-gray-900">{user.name || user.login}</p>
                <p className="text-xs text-gray-500">@{user.login}</p>
              </div>
              <img src={user.avatar} alt={user.login} className="w-10 h-10 rounded-full border-2 border-blue-100" />
              <button 
                onClick={logout} 
                className="text-gray-600 hover:text-red-600 transition-colors p-2 hover:bg-red-50 rounded-lg"
                title="Sign out"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {!groqKey && (
          <div className="bg-blue-50 border border-blue-200 rounded-2xl p-6 mb-6 shadow-sm">
            <div className="flex items-start gap-4 mb-4">
              <AlertCircle className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
              <div className="flex-1">
                <h3 className="font-semibold text-gray-900 mb-1">API Configuration Required</h3>
                <p className="text-sm text-gray-600 mb-3">Enter your Groq API key to enable AI-powered analysis</p>
                <div className="flex gap-3">
                  <input
                    type="password"
                    value={tempGroqKey}
                    onChange={e => setTempGroqKey(e.target.value)}
                    placeholder="Enter Groq API Key (gsk_...)"
                    className="flex-1 px-4 py-2.5 bg-white border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                  />
                  <button 
                    onClick={saveGroqKey}
                    className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-medium transition-colors"
                  >
                    Save Key
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-2xl p-4 mb-6 shadow-sm">
            <div className="flex justify-between items-start">
              <div className="flex gap-3">
                <AlertTriangle className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="font-semibold text-red-900 text-sm">Error</p>
                  <p className="text-sm text-red-700 mt-0.5">{error}</p>
                </div>
              </div>
              <button 
                onClick={() => setError('')}
                className="text-red-600 hover:text-red-800 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        <div className="flex gap-3 mb-8 bg-white p-2 rounded-2xl shadow-sm border border-gray-200">
          <button 
            onClick={() => setTab('repos')} 
            className={`flex-1 px-6 py-3 rounded-xl font-semibold transition-all ${
              tab === 'repos' 
                ? 'bg-blue-600 text-white shadow-md' 
                : 'text-gray-600 hover:bg-gray-50'
            }`}
          >
            <div className="flex items-center justify-center gap-2">
              <FileText className="w-4 h-4" />
              <span>Repositories</span>
              <span className="ml-1 text-xs opacity-75">({repos.length}/{CONFIG.MAX_REPOS})</span>
            </div>
          </button>
          <button 
            onClick={() => setTab('tasks')} 
            disabled={!activeRepo} 
            className={`flex-1 px-6 py-3 rounded-xl font-semibold transition-all ${
              tab === 'tasks' 
                ? 'bg-blue-600 text-white shadow-md' 
                : 'text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed'
            }`}
          >
            <div className="flex items-center justify-center gap-2">
              <Target className="w-4 h-4" />
              <span>Tasks</span>
              <span className="ml-1 text-xs opacity-75">({tasks.length})</span>
            </div>
          </button>
          <button 
            onClick={() => setTab('analysis')} 
            disabled={!activeRepo} 
            className={`flex-1 px-6 py-3 rounded-xl font-semibold transition-all ${
              tab === 'analysis' 
                ? 'bg-blue-600 text-white shadow-md' 
                : 'text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed'
            }`}
          >
            <div className="flex items-center justify-center gap-2">
              <TrendingUp className="w-4 h-4" />
              <span>Analysis</span>
            </div>
          </button>
          {analysis && (
            <button 
              onClick={() => setTab('results')} 
              className={`flex-1 px-6 py-3 rounded-xl font-semibold transition-all ${
                tab === 'results' 
                  ? 'bg-blue-600 text-white shadow-md' 
                  : 'text-gray-600 hover:bg-gray-50'
              }`}
            >
              <div className="flex items-center justify-center gap-2">
                <BarChart3 className="w-4 h-4" />
                <span>Results</span>
              </div>
            </button>
          )}
        </div>

        {/* REPOSITORIES TAB */}
        {tab === 'repos' && (
          <div className="space-y-6">
            <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm">
              <h2 className="text-xl font-bold mb-4 text-gray-900">Add Repository</h2>
              <div className="flex gap-3">
                <input
                  type="text"
                  value={newRepoUrl}
                  onChange={e => setNewRepoUrl(e.target.value)}
                  placeholder="https://github.com/owner/repository"
                  className="flex-1 px-4 py-3 bg-white border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  onKeyPress={e => e.key === 'Enter' && addRepo()}
                />
                <button
                  onClick={addRepo}
                  disabled={loading || repos.length >= CONFIG.MAX_REPOS}
                  className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-xl font-semibold transition-colors flex items-center gap-2"
                >
                  {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Plus className="w-5 h-5" />}
                  Add Repository
                </button>
              </div>
              {repos.length >= CONFIG.MAX_REPOS && (
                <p className="text-sm text-orange-600 mt-2">Maximum {CONFIG.MAX_REPOS} repositories reached</p>
              )}
            </div>

            <div className="grid gap-4">
              {repos.map(repo => (
                <div key={repo.fullName} className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm hover:shadow-md transition-shadow">
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-lg font-bold text-gray-900">{repo.name}</h3>
                        {repo.private && <Lock className="w-4 h-4 text-gray-500" />}
                        {activeRepo?.fullName === repo.fullName && (
                          <span className="px-2 py-1 bg-blue-100 text-blue-700 text-xs font-semibold rounded-lg">Active</span>
                        )}
                      </div>
                      <p className="text-sm text-gray-600 mb-3">{repo.description || 'No description'}</p>
                      <p className="text-xs text-gray-500">{repo.fullName}</p>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => {
                          setActiveRepo(repo);
                          setTab('tasks');
                        }}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
                      >
                        Select
                      </button>
                      <button
                        onClick={() => removeRepo(repo)}
                        className="px-3 py-2 bg-red-50 hover:bg-red-100 text-red-600 rounded-lg transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}

              {repos.length === 0 && (
                <div className="bg-gray-50 rounded-2xl p-12 text-center border-2 border-dashed border-gray-300">
                  <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">No Repositories Added</h3>
                  <p className="text-gray-600">Add your first GitHub repository to get started</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TASKS TAB */}
        {tab === 'tasks' && activeRepo && (
          <div className="space-y-6">
            <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm">
              <div className="flex justify-between items-center mb-4">
                <div>
                  <h2 className="text-xl font-bold text-gray-900">{activeRepo.name} - Tasks</h2>
                  <p className="text-sm text-gray-600">Manage team objectives and assignments</p>
                </div>
                <div className="flex gap-3">
                  {syncing && <Loader2 className="w-5 h-5 animate-spin text-blue-600" />}
                  <button
                    onClick={() => {
                      setEditTask({ 
                        title: '', 
                        description: '', 
                        assignedTo: [], 
                        priority: 'medium',
                        status: 'pending',
                        expectedOutcomes: []
                      });
                      setShowModal(true);
                    }}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-semibold transition-colors flex items-center gap-2"
                  >
                    <Plus className="w-4 h-4" />
                    New Task
                  </button>
                  <button
                    onClick={loadTasks}
                    disabled={syncing}
                    className="px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl font-semibold transition-colors flex items-center gap-2"
                  >
                    <RefreshCw className={`w-4 h-4 ${syncing ? 'animate-spin' : ''}`} />
                    Sync
                  </button>
                </div>
              </div>
              {lastSync && (
                <p className="text-xs text-gray-500">
                  <Clock className="w-3 h-3 inline mr-1" />
                  Last synced: {new Date(lastSync).toLocaleString()}
                </p>
              )}
            </div>

            <div className="grid gap-4">
              {tasks.map(task => (
                <div key={task.id} className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm hover:shadow-md transition-shadow">
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-lg font-bold text-gray-900">{task.title}</h3>
                        <span className={`px-3 py-1 rounded-lg text-xs font-semibold border ${getPriorityColor(task.priority)}`}>
                          {task.priority}
                        </span>
                        <span className={`px-3 py-1 rounded-lg text-xs font-semibold border flex items-center gap-1 ${getStatusColor(task.status)}`}>
                          {getStatusIcon(task.status)}
                          {task.status}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 mb-3">{task.description}</p>
                      <div className="flex flex-wrap gap-2 text-xs text-gray-500">
                        <span>Assigned: {task.assignedTo?.join(', ') || 'Unassigned'}</span>
                        <span>•</span>
                        <span>By: {task.createdBy}</span>
                        {task.expectedOutcomes?.length > 0 && (
                          <>
                            <span>•</span>
                            <span>Outcomes: {task.expectedOutcomes.length}</span>
                          </>
                        )}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => {
                          setEditTask(task);
                          setShowModal(true);
                        }}
                        className="px-3 py-2 bg-blue-50 hover:bg-blue-100 text-blue-600 rounded-lg transition-colors"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteTask(task.id)}
                        className="px-3 py-2 bg-red-50 hover:bg-red-100 text-red-600 rounded-lg transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}

              {tasks.length === 0 && (
                <div className="bg-gray-50 rounded-2xl p-12 text-center border-2 border-dashed border-gray-300">
                  <Target className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">No Tasks Yet</h3>
                  <p className="text-gray-600 mb-4">Create your first task to start tracking team objectives</p>
                  <button
                    onClick={() => {
                      setEditTask({ 
                        title: '', 
                        description: '', 
                        assignedTo: [], 
                        priority: 'medium',
                        status: 'pending',
                        expectedOutcomes: []
                      });
                      setShowModal(true);
                    }}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-semibold transition-colors inline-flex items-center gap-2"
                  >
                    <Plus className="w-5 h-5" />
                    Create First Task
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ANALYSIS TAB */}
        {tab === 'analysis' && activeRepo && (
          <div className="bg-white rounded-2xl p-8 border border-gray-200 shadow-sm">
            <h2 className="text-2xl font-bold mb-6 text-gray-900">Performance Analysis</h2>
            <div className="space-y-4 mb-6">
              <div className="bg-blue-50 rounded-xl p-4 border border-blue-200">
                <p className="text-sm text-gray-700">
                  <strong>Repository:</strong> {activeRepo.fullName}
                </p>
                <p className="text-sm text-gray-700 mt-1">
                  <strong>Tasks:</strong> {tasks.length} configured
                </p>
                {!groqKey && (
                  <p className="text-sm text-orange-600 mt-2">
                    ⚠️ Groq API key required for analysis
                  </p>
                )}
              </div>
            </div>
            <button
              onClick={analyze}
              disabled={loading || !groqKey}
              className="w-full px-6 py-4 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-xl font-bold text-lg transition-colors flex items-center justify-center gap-3"
            >
              {loading ? (
                <>
                  <Loader2 className="w-6 h-6 animate-spin" />
                  Analyzing with AI...
                </>
              ) : (
                <>
                  <TrendingUp className="w-6 h-6" />
                  Run Performance Analysis
                </>
              )}
            </button>
          </div>
        )}

        {/* RESULTS TAB */}
        {tab === 'results' && analysis && (
          <div className="space-y-6">
            <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm">
              <h2 className="text-2xl font-bold mb-2 text-gray-900">Analysis Results</h2>
              <p className="text-sm text-gray-600">
                Analyzed: {new Date(analysis.metadata.analyzedAt).toLocaleString()}
              </p>
            </div>

            {/* Contributors Performance */}
            <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm">
              <h3 className="text-xl font-bold mb-4 text-gray-900">Team Performance</h3>
              <div className="space-y-4">
                {analysis.analysis.contributors.map((contrib, idx) => (
                  <div key={idx} className="border border-gray-200 rounded-xl p-5">
                    <div className="flex justify-between items-start mb-3">
                      <h4 className="text-lg font-semibold text-gray-900">{contrib.name}</h4>
                      <div className="text-right">
                        <div className="text-2xl font-bold text-blue-600">{contrib.overallScore}</div>
                        <div className="text-xs text-gray-500">Overall Score</div>
                      </div>
                    </div>
                    <p className="text-sm text-gray-700 mb-4">{contrib.impact}</p>
                    
                    {contrib.taskPerformance && (
                      <div className="bg-blue-50 rounded-lg p-4 mb-4 border border-blue-200">
                        <h5 className="font-semibold text-gray-900 mb-2">Task Performance</h5>
                        <div className="grid grid-cols-2 gap-3 text-sm mb-2">
                          <div>Task Alignment: <strong>{contrib.taskPerformance.taskAlignmentScore}</strong></div>
                          <div>Code Quality: <strong>{contrib.taskPerformance.codeQualityScore}</strong></div>
                          <div>Timeliness: <strong>{contrib.taskPerformance.timelinessScore}</strong></div>
                          <div>Efficiency: <strong>{contrib.taskPerformance.efficiencyScore}</strong></div>
                        </div>
                        <p className="text-xs text-gray-700">{contrib.taskPerformance.taskSpecificAnalysis}</p>
                      </div>
                    )}
                    
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <h5 className="font-semibold text-gray-900 text-sm mb-2">Strengths</h5>
                        <ul className="text-xs text-gray-700 space-y-1">
                          {contrib.strengths.map((s, i) => <li key={i}>• {s}</li>)}
                        </ul>
                      </div>
                      <div>
                        <h5 className="font-semibold text-gray-900 text-sm mb-2">Areas for Improvement</h5>
                        <ul className="text-xs text-gray-700 space-y-1">
                          {contrib.areasForImprovement.map((a, i) => <li key={i}>• {a}</li>)}
                        </ul>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Code Health & Recommendations */}
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm">
                <h3 className="text-xl font-bold mb-4 text-gray-900">Code Health</h3>
                <div className="text-4xl font-bold text-green-600 mb-2">{analysis.analysis.codeHealth.score}</div>
                <p className="text-sm text-gray-700 mb-4">{analysis.analysis.codeHealth.insights}</p>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span>Commit Frequency:</span>
                    <strong>{analysis.analysis.codeHealth.metrics.commitFrequency}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Code Quality:</span>
                    <strong>{analysis.analysis.codeHealth.metrics.codeQuality}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Collaboration:</span>
                    <strong>{analysis.analysis.codeHealth.metrics.collaboration}</strong>
                  </div>
                </div>
              </div>

              <div className="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm">
                <h3 className="text-xl font-bold mb-4 text-gray-900">Recommendations</h3>
                <ul className="space-y-3">
                  {analysis.analysis.recommendations.map((rec, idx) => (
                    <li key={idx} className="flex gap-3">
                      <CheckCircle2 className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
                      <span className="text-sm text-gray-700">{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Task Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-8 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-2xl font-bold text-gray-900">
                {editTask?.id ? 'Edit Task' : 'New Task'}
              </h3>
              <button onClick={() => setShowModal(false)} className="text-gray-500 hover:text-gray-700">
                <X className="w-6 h-6" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Title</label>
                <input
                  type="text"
                  value={editTask?.title || ''}
                  onChange={e => setEditTask({...editTask, title: e.target.value})}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Task title"
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Description</label>
                <textarea
                  value={editTask?.description || ''}
                  onChange={e => setEditTask({...editTask, description: e.target.value})}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500"
                  rows="4"
                  placeholder="Detailed description"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Priority</label>
                  <select
                    value={editTask?.priority || 'medium'}
                    onChange={e => setEditTask({...editTask, priority: e.target.value})}
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Status</label>
                  <select
                    value={editTask?.status || 'pending'}
                    onChange={e => setEditTask({...editTask, status: e.target.value})}
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="pending">Pending</option>
                    <option value="in-progress">In Progress</option>
                    <option value="completed">Completed</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                  Assigned To (comma-separated usernames)
                </label>
                <input
                  type="text"
                  value={editTask?.assignedTo?.join(', ') || ''}
                  onChange={e => setEditTask({...editTask, assignedTo: e.target.value.split(',').map(s => s.trim()).filter(Boolean)})}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="user1, user2, user3"
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                  Expected Outcomes (comma-separated)
                </label>
                <input
                  type="text"
                  value={editTask?.expectedOutcomes?.join(', ') || ''}
                  onChange={e => setEditTask({...editTask, expectedOutcomes: e.target.value.split(',').map(s => s.trim()).filter(Boolean)})}
                  className="w-full px-4 py-3 border border-gray-300 rounded-xl outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="outcome1, outcome2, outcome3"
                />
              </div>

              <div className="flex gap-3 pt-4">
                <button
                  onClick={saveTask}
                  disabled={!editTask?.title}
                  className="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-xl font-semibold transition-colors flex items-center justify-center gap-2"
                >
                  <Save className="w-5 h-5" />
                  Save Task
                </button>
                <button
                  onClick={() => setShowModal(false)}
                  className="px-6 py-3 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-xl font-semibold transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {confirmDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-2xl p-8 max-w-md w-full">
            <div className="flex items-center gap-4 mb-6">
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                <AlertTriangle className="w-6 h-6 text-red-600" />
              </div>
              <div>
                <h3 className="text-xl font-bold text-gray-900">Delete Task?</h3>
                <p className="text-sm text-gray-600">This action cannot be undone</p>
              </div>
            </div>

            <div className="flex gap-3">
              <button
                onClick={confirmDeleteTask}
                className="flex-1 px-6 py-3 bg-red-600 hover:bg-red-700 text-white rounded-xl font-semibold transition-colors"
              >
                Delete
              </button>
              <button
                onClick={() => setConfirmDelete(null)}
                className="flex-1 px-6 py-3 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-xl font-semibold transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}