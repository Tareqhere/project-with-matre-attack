import { useState, useEffect, useCallback } from 'react';
import {
  Shield, Code, Link as LinkIcon, AlertTriangle,
  Menu, Settings, User, History,
  Download, Trash2, ChevronDown, ChevronUp,
  X, Loader2, CheckCircle, XCircle, LogOut
} from 'lucide-react';
import * as api from './api';
import type { InputType, Report, AnalysisResult, AuthState } from './types';

// ═══════════════════════════════════════════════
// Severity color mapping for UI badges
// ═══════════════════════════════════════════════
const SEVERITY_COLORS: Record<string, string> = {
  None: 'bg-gray-100 text-gray-700',
  Low: 'bg-green-100 text-green-700',
  Medium: 'bg-yellow-100 text-yellow-800',
  High: 'bg-orange-100 text-orange-700',
  Critical: 'bg-red-100 text-red-700',
};

const CONFIDENCE_COLORS: Record<string, string> = {
  Low: 'bg-gray-100 text-gray-600',
  Medium: 'bg-blue-100 text-blue-700',
  High: 'bg-emerald-100 text-emerald-700',
};

// ═══════════════════════════════════════════════
// Auth Modal Component
// ═══════════════════════════════════════════════
function AuthModal({ mode, onClose, onSuccess }: {
  mode: 'signin' | 'signup';
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mode === 'signup') {
        await api.signup(email, password);
      } else {
        await api.login(email, password);
      }
      onSuccess();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold text-gray-900">
            {mode === 'signup' ? 'Create Account' : 'Sign In'}
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded-lg" aria-label="Close">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
              required
              autoComplete="email"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
              required
              minLength={8}
              autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
            />
            {mode === 'signup' && (
              <p className="text-xs text-gray-500 mt-1">
                Min 8 characters, 1 uppercase, 1 lowercase, 1 digit
              </p>
            )}
          </div>
          {error && (
            <div className="text-red-600 text-sm bg-red-50 px-3 py-2 rounded-lg">{error}</div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {loading && <Loader2 className="w-4 h-4 animate-spin" />}
            {mode === 'signup' ? 'Create Account' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════
// Report Display Component
// ═══════════════════════════════════════════════

const SEVERITY_TO_NUM: Record<string, number> = {
  None: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

function ReportView({ result, onDownloadJSON }: {
  result: AnalysisResult;
  onDownloadJSON: () => void;
}) {
  const [expandedPatches, setExpandedPatches] = useState<Record<number, boolean>>({});

  const togglePatch = (index: number) => {
    setExpandedPatches((prev) => ({ ...prev, [index]: !prev[index] }));
  };

  // Compute aggregate stats
  const maxCvss = result.vulnerabilities.reduce((max, v) => {
    if (v.cvss_score !== null && v.cvss_score > max) return v.cvss_score;
    return max;
  }, -1);

  const topSeverity = result.vulnerabilities.reduce((highest, v) => {
    if (!v.severity_label) return highest;
    if (!highest) return v.severity_label;
    if (SEVERITY_TO_NUM[v.severity_label] > SEVERITY_TO_NUM[highest]) {
      return v.severity_label;
    }
    return highest;
  }, null as string | null);

  const displayCvss = maxCvss >= 0 ? maxCvss.toFixed(1) : 'N/A';

  return (
    <div className="mt-8 space-y-4 max-w-4xl mx-auto">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Vulnerability Status */}
        <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm">
          <div className="text-sm text-gray-500 mb-1">Status</div>
          <div className="flex items-center gap-2">
            {result.is_vulnerable ? (
              <XCircle className="w-5 h-5 text-red-500" />
            ) : (
              <CheckCircle className="w-5 h-5 text-green-500" />
            )}
            <span className={`font-semibold ${result.is_vulnerable ? 'text-red-700' : 'text-green-700'}`}>
              {result.is_vulnerable ? 'Vulnerabilities Found' : 'No Issues Found'}
            </span>
          </div>
        </div>

        {/* Highest CVSS Score */}
        <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm">
          <div className="text-sm text-gray-500 mb-1">Highest CVSS Score</div>
          <div className="flex items-center gap-2">
            <span className="text-2xl font-bold text-gray-900">
              {displayCvss}
            </span>
            {topSeverity && (
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${SEVERITY_COLORS[topSeverity] || 'bg-gray-100 text-gray-600'}`}>
                {topSeverity}
              </span>
            )}
            <span className="text-xs text-gray-500 ml-auto">
              ({result.vulnerabilities.length} issue{result.vulnerabilities.length === 1 ? '' : 's'})
            </span>
          </div>
        </div>
      </div>

      {result.vulnerabilities.map((vuln, index) => (
        <div key={index} className="mt-8 pt-8 border-t-2 border-dashed border-gray-200">
          <h2 className="text-xl font-bold text-gray-800 mb-4">
            Vulnerability #{index + 1}: {vuln.vulnerability_type || 'Unknown Type'}
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            {/* CVSS Score */}
            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm">
              <div className="text-sm text-gray-500 mb-1">CVSS Score</div>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold text-gray-900">
                  {vuln.cvss_score !== null ? vuln.cvss_score.toFixed(1) : 'N/A'}
                </span>
                {vuln.severity_label && (
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${SEVERITY_COLORS[vuln.severity_label] || 'bg-gray-100 text-gray-600'}`}>
                    {vuln.severity_label}
                  </span>
                )}
              </div>
            </div>

            {/* Confidence */}
            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm">
              <div className="text-sm text-gray-500 mb-1">Confidence</div>
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${CONFIDENCE_COLORS[vuln.confidence] || 'bg-gray-100 text-gray-600'}`}>
                {vuln.confidence}
              </span>
            </div>

            {/* OWASP Category */}
            {vuln.owasp_category && (
              <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm">
                <div className="text-sm text-gray-500 mb-1">OWASP Category</div>
                <div className="font-medium text-gray-900 line-clamp-2">{vuln.owasp_category}</div>
              </div>
            )}
          </div>

          {/* CVSS Vector */}
          {vuln.cvss_vector && (
            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm mb-4">
              <div className="text-sm text-gray-500 mb-1">CVSS Vector</div>
              <code className="text-sm text-gray-800 bg-gray-100 px-2 py-1 rounded font-mono">
                {vuln.cvss_vector}
              </code>
            </div>
          )}

          {/* Explanation */}
          <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">Explanation</h3>
            <p className="text-gray-700 leading-relaxed whitespace-pre-wrap">{vuln.explanation}</p>
          </div>

          {/* Secure Patch (expandable) */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden mb-4">
            <button
              onClick={() => togglePatch(index)}
              className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors"
            >
              <h3 className="text-lg font-semibold text-gray-900">Secure Patch / Remediation</h3>
              {expandedPatches[index] ? <ChevronUp className="w-5 h-5 text-gray-500" /> : <ChevronDown className="w-5 h-5 text-gray-500" />}
            </button>
            {expandedPatches[index] && (
              <div className="px-5 pb-5 border-t border-gray-100">
                <pre className="bg-[#1e1e1e] text-gray-300 p-4 rounded-lg text-sm font-mono overflow-x-auto mt-3 whitespace-pre-wrap">
                  {vuln.secure_patch}
                </pre>
              </div>
            )}
          </div>

          {/* Recommendations */}
          {vuln.recommendations.length > 0 && (
            <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">Recommendations</h3>
              <ul className="space-y-2">
                {vuln.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-gray-700">
                    <span className="mt-1 w-5 h-5 flex-shrink-0 rounded-full bg-blue-100 text-blue-700 text-xs flex items-center justify-center font-medium">
                      {i + 1}
                    </span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* MITRE ATT&CK Mapping */}
          {vuln.mitre_attack_mapping && vuln.mitre_attack_mapping.length > 0 && (
            <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">MITRE ATT&CK Mapping</h3>
              <div className="space-y-4">
                {vuln.mitre_attack_mapping.map((mapping, i) => (
                  <div key={i} className="flex flex-col gap-2 p-3 bg-gray-50 rounded-lg border border-gray-100">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs font-mono font-bold">
                        {mapping.technique_id}
                      </span>
                      <span className="font-medium text-gray-800">{mapping.technique_name}</span>
                    </div>
                    <p className="text-sm text-gray-600 leading-relaxed">{mapping.explanation}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Notes */}
          {vuln.notes && (
            <div className="bg-blue-50 rounded-xl border border-blue-200 p-5">
              <h3 className="text-sm font-semibold text-blue-800 mb-2">Additional Notes</h3>
              <p className="text-blue-700 text-sm">{vuln.notes}</p>
            </div>
          )}
        </div>
      ))}

      {/* Download Buttons */}
      <div className="flex gap-3 justify-center pt-6">
        <button
          onClick={onDownloadJSON}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors shadow-sm"
        >
          <Download className="w-4 h-4" />
          Download JSON
        </button>
        <button
          onClick={() => window.print()}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors shadow-sm"
        >
          <Download className="w-4 h-4" />
          Download PDF
        </button>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════
// History Panel Component
// ═══════════════════════════════════════════════
function HistoryPanel({ onClose, onSelectReport }: {
  onClose: () => void;
  onSelectReport: (report: Report) => void;
}) {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getReports()
      .then((data) => setReports(data.reports))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (id: string) => {
    try {
      await api.deleteReport(id);
      setReports((prev) => prev.filter((r) => r.id !== id));
    } catch {
      // ignore
    }
  };

  const getTopSeverity = (result: AnalysisResult) => {
    const highest = result.vulnerabilities.reduce((max, v) => {
      if (!v.severity_label) return max;
      if (!max) return v.severity_label;
      if (SEVERITY_TO_NUM[v.severity_label] > SEVERITY_TO_NUM[max]) {
        return v.severity_label;
      }
      return max;
    }, null as string | null);
    return highest;
  };

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="fixed inset-0 bg-black/30" onClick={onClose} />
      <div className="relative ml-auto w-full max-w-md bg-white h-full shadow-xl overflow-y-auto z-10">
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Report History</h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded-lg" aria-label="Close history">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <div className="p-6">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
            </div>
          ) : reports.length === 0 ? (
            <p className="text-gray-500 text-center py-12">No reports yet</p>
          ) : (
            <div className="space-y-3">
              {reports.map((report) => {
                const topSeverity = getTopSeverity(report.result);
                return (
                  <div
                    key={report.id}
                    className="bg-gray-50 rounded-lg p-4 border border-gray-200 hover:border-blue-300 transition-colors"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <button
                        onClick={() => { onSelectReport(report); onClose(); }}
                        className="text-left flex-1"
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-medium px-2 py-0.5 rounded bg-gray-200 text-gray-600 uppercase">
                            {report.inputType}
                          </span>
                          {topSeverity && (
                            <span className={`text-xs font-medium px-2 py-0.5 rounded ${SEVERITY_COLORS[topSeverity] || ''}`}>
                              {topSeverity}
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-gray-700 line-clamp-2">{report.contentPreview}</p>
                        <p className="text-xs text-gray-400 mt-1">
                          {new Date(report.createdAt).toLocaleString()}
                        </p>
                      </button>
                      <button
                        onClick={() => handleDelete(report.id)}
                        className="p-1.5 hover:bg-red-50 rounded-lg text-gray-400 hover:text-red-500 transition-colors flex-shrink-0"
                        aria-label="Delete report"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════
// Main App Component — preserves Figma UI
// ═══════════════════════════════════════════════
export default function App() {
  const [inputType, setInputType] = useState<InputType>('code');
  const [code, setCode] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const [authModal, setAuthModal] = useState<'signin' | 'signup' | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [auth, setAuth] = useState<AuthState>({ authenticated: false, user: null });
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');

  // Check auth status on mount
  const checkAuth = useCallback(async () => {
    try {
      const me = await api.getMe();
      setAuth(me);
    } catch {
      setAuth({ authenticated: false, user: null });
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  const handleAnalyze = async () => {
    if (!code.trim()) return;
    setError('');
    setAnalysisResult(null);
    setAnalyzing(true);
    try {
      const response = await api.analyze(inputType, code);
      setAnalysisResult(response.result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please try again.');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.logout();
      setAuth({ authenticated: false, user: null });
      setMenuOpen(false);
    } catch {
      // ignore
    }
  };

  const handleDownloadJSON = () => {
    if (!analysisResult) return;
    const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulnerability-report.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSelectReport = (report: Report) => {
    setAnalysisResult(report.result);
  };

  const getPlaceholder = () => {
    switch (inputType) {
      case 'code':
        return 'Paste your code here...';
      case 'link':
        return 'Enter repository or file URL...';
      case 'cve':
        return 'Enter CVE ID (e.g., CVE-2024-1234)...';
    }
  };

  const getFileName = () => {
    switch (inputType) {
      case 'code':
        return 'input.code';
      case 'link':
        return 'input.url';
      case 'cve':
        return 'input.cve';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Header */}
      <header className="pt-16 pb-12 px-6">
        {/* Top Navigation */}
        <div className="fixed top-0 left-0 right-0 bg-white border-b border-gray-200 z-50">
          <div className="max-w-7xl mx-auto flex items-center justify-between px-[24px] py-[10px]">
            {/* Left Menu */}
            <div className="relative">
              <button
                onClick={() => setMenuOpen(!menuOpen)}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                aria-label="Menu"
              >
                <Menu className="w-6 h-6 text-gray-700" />
              </button>

              {/* Dropdown Menu */}
              {menuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-10"
                    onClick={() => setMenuOpen(false)}
                  />
                  <div className="absolute left-0 top-full mt-2 w-48 bg-white rounded-lg shadow-lg border border-gray-200 py-2 z-20">
                    <button
                      onClick={() => { setMenuOpen(false); }}
                      className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-3 text-gray-700"
                    >
                      <Settings className="w-4 h-4" />
                      Settings
                    </button>
                    {auth.authenticated && (
                      <button
                        onClick={() => { setMenuOpen(false); }}
                        className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-3 text-gray-700"
                      >
                        <User className="w-4 h-4" />
                        Account
                      </button>
                    )}
                    <button
                      onClick={() => { setMenuOpen(false); setHistoryOpen(true); }}
                      className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-3 text-gray-700"
                    >
                      <History className="w-4 h-4" />
                      History
                    </button>
                    {auth.authenticated && (
                      <button
                        onClick={handleLogout}
                        className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-3 text-red-600"
                      >
                        <LogOut className="w-4 h-4" />
                        Sign Out
                      </button>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* Right Auth Buttons */}
            <div className="flex items-center gap-3">
              {auth.authenticated ? (
                <div className="flex items-center gap-3">
                  <span className="text-sm text-gray-600">{auth.user?.email}</span>
                  <button
                    onClick={handleLogout}
                    className="px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
                  >
                    Sign Out
                  </button>
                </div>
              ) : (
                <>
                  <button
                    onClick={() => setAuthModal('signin')}
                    className="px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
                  >
                    Sign In
                  </button>
                  <button
                    onClick={() => setAuthModal('signup')}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    Sign Up
                  </button>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Main Header Content */}
        <div className="max-w-4xl mx-auto text-center mt-10">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-8 h-8 text-blue-600" />
            <h1 className="text-4xl text-gray-900">AI Secure Code Analyzer</h1>
          </div>
          <p className="text-gray-600 text-lg">
            Educational Vulnerability Detection and Security Report
          </p>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 px-6 pb-16">
        <div className="max-w-4xl mx-auto">
          {/* Input Type Tabs */}
          <div className="flex gap-2 mb-6">
            <button
              onClick={() => { setInputType('code'); setCode(''); setAnalysisResult(null); setError(''); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                inputType === 'code'
                  ? 'bg-blue-600 text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-100 border border-gray-200'
              }`}
            >
              <Code className="w-4 h-4" />
              Code
            </button>
            <button
              onClick={() => { setInputType('link'); setCode(''); setAnalysisResult(null); setError(''); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                inputType === 'link'
                  ? 'bg-blue-600 text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-100 border border-gray-200'
              }`}
            >
              <LinkIcon className="w-4 h-4" />
              Link
            </button>
            <button
              onClick={() => { setInputType('cve'); setCode(''); setAnalysisResult(null); setError(''); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                inputType === 'cve'
                  ? 'bg-blue-600 text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-100 border border-gray-200'
              }`}
            >
              <AlertTriangle className="w-4 h-4" />
              CVE
            </button>
          </div>

          {/* Code Editor */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden mb-6">
            <div className="bg-[#1e1e1e] px-4 py-3 border-b border-gray-700">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
                <span className="ml-3 text-gray-400 text-sm">{getFileName()}</span>
              </div>
            </div>
            {inputType === 'code' ? (
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={getPlaceholder()}
                className="w-full h-72 bg-[#1e1e1e] text-gray-300 p-6 font-mono text-sm resize-none focus:outline-none placeholder:text-gray-600"
                spellCheck={false}
              />
            ) : (
              <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={getPlaceholder()}
                className="w-full bg-[#1e1e1e] text-gray-300 px-6 py-4 font-mono text-sm focus:outline-none placeholder:text-gray-600"
                spellCheck={false}
              />
            )}
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 text-sm">
              {error}
            </div>
          )}

          {/* Analyze Button */}
          <div className="flex justify-center">
            <button
              onClick={handleAnalyze}
              disabled={analyzing || !code.trim()}
              className="px-8 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors shadow-sm font-medium text-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {analyzing && <Loader2 className="w-5 h-5 animate-spin" />}
              {analyzing ? 'Analyzing...' : 'Analyze Code'}
            </button>
          </div>

          {/* Analysis Result */}
          {analysisResult && (
            <ReportView result={analysisResult} onDownloadJSON={handleDownloadJSON} />
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="py-6 px-6 text-center text-gray-500 text-sm">
        <p>Educational purposes only • Learn secure coding practices</p>
      </footer>

      {/* Auth Modal */}
      {authModal && (
        <AuthModal
          mode={authModal}
          onClose={() => setAuthModal(null)}
          onSuccess={checkAuth}
        />
      )}

      {/* History Panel */}
      {historyOpen && (
        <HistoryPanel
          onClose={() => setHistoryOpen(false)}
          onSelectReport={handleSelectReport}
        />
      )}
    </div>
  );
}
