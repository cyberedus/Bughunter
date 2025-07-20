import React, { useState, useEffect } from 'react';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const ScanDashboard = () => {
  const [scanConfig, setScanConfig] = useState({
    name: '',
    description: '',
    scan_type: 'Web_Application',
    target_url: '',
    network_range: '',
    code_repository: '',
    scan_depth: 'Standard',
    gpt4_analysis_enabled: true
  });

  const [activeScans, setActiveScans] = useState([]);
  const [scanResults, setScanResults] = useState({});
  const [isScanning, setIsScanning] = useState(false);
  const [gpt4Status, setGpt4Status] = useState({ connected: false, testing: false });

  useEffect(() => {
    checkGPT4Status();
    loadActiveScans();
  }, []);

  const checkGPT4Status = async () => {
    setGpt4Status(prev => ({ ...prev, testing: true }));
    try {
      const response = await axios.post(`${API}/gpt4/test-connection`);
      setGpt4Status({ connected: response.data.success, testing: false });
    } catch (error) {
      setGpt4Status({ connected: false, testing: false });
    }
  };

  const loadActiveScans = async () => {
    // This would load active scans from the backend
    // For now, we'll simulate some data
    setActiveScans([]);
  };

  const handleInputChange = (field, value) => {
    setScanConfig(prev => ({ ...prev, [field]: value }));
  };

  const startScan = async () => {
    if (!scanConfig.name) {
      alert('Please provide a scan name');
      return;
    }

    if (scanConfig.scan_type === 'Web_Application' && !scanConfig.target_url) {
      alert('Please provide a target URL for web application scanning');
      return;
    }

    if (scanConfig.scan_type === 'Network_Infrastructure' && !scanConfig.network_range) {
      alert('Please provide a network range for infrastructure scanning');
      return;
    }

    setIsScanning(true);
    try {
      const response = await axios.post(`${API}/scan/create`, scanConfig);
      if (response.data.success) {
        alert(`Scan "${scanConfig.name}" created successfully! Scan ID: ${response.data.scan_id}`);
        // Reset form
        setScanConfig({
          name: '',
          description: '',
          scan_type: 'Web_Application',
          target_url: '',
          network_range: '',
          code_repository: '',
          scan_depth: 'Standard',
          gpt4_analysis_enabled: true
        });
        loadActiveScans();
      }
    } catch (error) {
      alert(`Failed to create scan: ${error.response?.data?.detail || error.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const testGPT4Analysis = async () => {
    try {
      const testPayload = {
        type: 'XSS',
        details: 'Reflected XSS vulnerability in search parameter',
        context: 'E-commerce website search functionality',
        evidence: 'Parameter "q" reflects user input without proper encoding'
      };

      const response = await axios.post(`${API}/gpt4/analyze-vulnerability`, testPayload);
      
      if (response.data.success) {
        alert('GPT-4 Analysis Test Successful! Check console for detailed analysis.');
        console.log('GPT-4 Analysis Result:', response.data.gpt4_analysis);
      }
    } catch (error) {
      alert(`GPT-4 test failed: ${error.response?.data?.detail || error.message}`);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-purple-500 bg-clip-text text-transparent mb-2">
          VulnScan Enterprise
        </h1>
        <p className="text-gray-400 text-lg">
          AI-Powered Vulnerability Scanner for Bug Hunters & Security Professionals
        </p>
        
        {/* GPT-4 Status Indicator */}
        <div className="mt-4 flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${gpt4Status.connected ? 'bg-green-500' : 'bg-red-500'}`}></div>
            <span className="text-sm">
              GPT-4 Status: {gpt4Status.testing ? 'Testing...' : (gpt4Status.connected ? 'Connected' : 'Disconnected')}
            </span>
          </div>
          <button 
            onClick={testGPT4Analysis}
            className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-xs rounded transition-colors"
          >
            Test GPT-4 Analysis
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Scan Configuration Panel */}
        <div className="lg:col-span-2">
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h2 className="text-2xl font-bold mb-6 text-cyan-400">Configure New Scan</h2>
            
            <div className="space-y-6">
              {/* Basic Info */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Scan Name</label>
                  <input
                    type="text"
                    value={scanConfig.name}
                    onChange={(e) => handleInputChange('name', e.target.value)}
                    placeholder="My Security Scan"
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Scan Type</label>
                  <select
                    value={scanConfig.scan_type}
                    onChange={(e) => handleInputChange('scan_type', e.target.value)}
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    <option value="Web_Application">Web Application</option>
                    <option value="Network_Infrastructure">Network Infrastructure</option>
                    <option value="Static_Code_Analysis">Static Code Analysis</option>
                    <option value="Comprehensive">Comprehensive Scan</option>
                  </select>
                </div>
              </div>

              {/* Description */}
              <div>
                <label className="block text-sm font-medium mb-2">Description</label>
                <textarea
                  value={scanConfig.description}
                  onChange={(e) => handleInputChange('description', e.target.value)}
                  placeholder="Optional description of what you're scanning and why..."
                  rows={2}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>

              {/* Target Configuration */}
              {scanConfig.scan_type === 'Web_Application' && (
                <div>
                  <label className="block text-sm font-medium mb-2">Target URL</label>
                  <input
                    type="url"
                    value={scanConfig.target_url}
                    onChange={(e) => handleInputChange('target_url', e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                </div>
              )}

              {scanConfig.scan_type === 'Network_Infrastructure' && (
                <div>
                  <label className="block text-sm font-medium mb-2">Network Range</label>
                  <input
                    type="text"
                    value={scanConfig.network_range}
                    onChange={(e) => handleInputChange('network_range', e.target.value)}
                    placeholder="192.168.1.0/24 or 10.0.0.1-10.0.0.100"
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                </div>
              )}

              {scanConfig.scan_type === 'Static_Code_Analysis' && (
                <div>
                  <label className="block text-sm font-medium mb-2">Code Repository</label>
                  <input
                    type="text"
                    value={scanConfig.code_repository}
                    onChange={(e) => handleInputChange('code_repository', e.target.value)}
                    placeholder="https://github.com/user/repo or /path/to/code"
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                </div>
              )}

              {/* Advanced Options */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Scan Depth</label>
                  <select
                    value={scanConfig.scan_depth}
                    onChange={(e) => handleInputChange('scan_depth', e.target.value)}
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    <option value="Surface">Surface (Fast)</option>
                    <option value="Standard">Standard (Recommended)</option>
                    <option value="Deep">Deep (Comprehensive)</option>
                  </select>
                </div>
                <div className="flex items-center">
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={scanConfig.gpt4_analysis_enabled}
                      onChange={(e) => handleInputChange('gpt4_analysis_enabled', e.target.checked)}
                      className="w-4 h-4 text-cyan-500 bg-gray-700 border-gray-600 rounded focus:ring-cyan-500"
                    />
                    <span className="text-sm">Enable GPT-4 Analysis</span>
                  </label>
                </div>
              </div>

              {/* Start Scan Button */}
              <div className="pt-4">
                <button
                  onClick={startScan}
                  disabled={isScanning}
                  className="w-full md:w-auto px-8 py-3 bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold rounded-lg transition-all duration-200 transform hover:scale-105"
                >
                  {isScanning ? 'Creating Scan...' : 'Start Vulnerability Scan'}
                </button>
              </div>
            </div>
          </div>

          {/* Features Showcase */}
          <div className="mt-8 bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 className="text-xl font-bold mb-4 text-purple-400">Enterprise Features</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
              <div className="p-4 bg-gray-700 rounded-lg">
                <div className="text-2xl mb-2">🎯</div>
                <div className="text-sm font-medium">Zero False Positives</div>
              </div>
              <div className="p-4 bg-gray-700 rounded-lg">
                <div className="text-2xl mb-2">🧠</div>
                <div className="text-sm font-medium">GPT-4 Intelligence</div>
              </div>
              <div className="p-4 bg-gray-700 rounded-lg">
                <div className="text-2xl mb-2">🚀</div>
                <div className="text-sm font-medium">Custom Payloads</div>
              </div>
              <div className="p-4 bg-gray-700 rounded-lg">
                <div className="text-2xl mb-2">💎</div>
                <div className="text-sm font-medium">Zero-Day Ready</div>
              </div>
            </div>
          </div>
        </div>

        {/* Active Scans & Quick Stats */}
        <div className="space-y-6">
          {/* Quick Actions */}
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 className="text-xl font-bold mb-4 text-green-400">Quick Actions</h3>
            <div className="space-y-3">
              <button 
                onClick={checkGPT4Status}
                className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-sm rounded-lg transition-colors"
              >
                Refresh GPT-4 Status
              </button>
              <button className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-sm rounded-lg transition-colors">
                View Documentation
              </button>
              <button className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-700 text-sm rounded-lg transition-colors">
                Export Reports
              </button>
            </div>
          </div>

          {/* Active Scans */}
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 className="text-xl font-bold mb-4 text-yellow-400">Active Scans</h3>
            {activeScans.length === 0 ? (
              <p className="text-gray-400 text-center py-4">No active scans</p>
            ) : (
              <div className="space-y-3">
                {activeScans.map((scan, index) => (
                  <div key={index} className="p-3 bg-gray-700 rounded-lg">
                    <div className="flex justify-between items-center mb-2">
                      <span className="font-medium">{scan.name}</span>
                      <span className="text-sm text-green-400">{scan.status}</span>
                    </div>
                    <div className="w-full bg-gray-600 rounded-full h-2">
                      <div 
                        className="bg-cyan-500 h-2 rounded-full" 
                        style={{width: `${scan.progress}%`}}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Stats */}
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h3 className="text-xl font-bold mb-4 text-red-400">Scanner Stats</h3>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span>Total Scans</span>
                <span className="text-cyan-400 font-bold">0</span>
              </div>
              <div className="flex justify-between">
                <span>Vulnerabilities Found</span>
                <span className="text-red-400 font-bold">0</span>
              </div>
              <div className="flex justify-between">
                <span>False Positives Filtered</span>
                <span className="text-green-400 font-bold">0</span>
              </div>
              <div className="flex justify-between">
                <span>GPT-4 Analyses</span>
                <span className="text-purple-400 font-bold">0</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanDashboard;