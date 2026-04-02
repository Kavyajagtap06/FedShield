import { CircularProgressbar, buildStyles } from "react-circular-progressbar";
import "react-circular-progressbar/dist/styles.css";
import React, { useState } from "react";
import axios from "axios";
import "./dashboard.css";

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
} from "recharts";

function Dashboard() {
  const [url, setUrl] = useState("");
  const [probability, setProbability] = useState(null);
  const [reasons, setReasons] = useState([]);
  const [loading, setLoading] = useState(false);
  const [domainInfo, setDomainInfo] = useState(null);
  const [ipInfo, setIpInfo] = useState({});
  const [riskFactors, setRiskFactors] = useState([]);
  const [urlReachable, setUrlReachable] = useState(true);
  const [baseProbability, setBaseProbability] = useState(null);
  const [threatIntel, setThreatIntel] = useState(null);
  const [layers, setLayers] = useState(null);

  const formatAge = (days) => {
    if (!days && days !== 0) return "Unknown";
    if (days < 0) return "Unknown";

    const years = Math.floor(days / 365);
    const months = Math.floor((days % 365) / 30);

    if (years > 0) {
      return `${years} years ${months} months`;
    }

    return `${days} days`;
  };

  const handlePredict = async () => {
    if (!url) {
      alert("Please enter a URL.");
      return;
    }

    try {
      setLoading(true);

      const response = await axios.post("http://127.0.0.1:5000/predict", {
        url: url,
      });

      console.log("API Response:", response.data);

      setProbability(response.data.probability);
      setBaseProbability(response.data.base_probability);
      setReasons(response.data.reasons || []);
      setRiskFactors(response.data.risk_factors || []);
      setUrlReachable(response.data.url_reachable !== false);
      setDomainInfo(response.data.domain_intelligence || null);
      setIpInfo(response.data.ip_info || {});
      setThreatIntel(response.data.threat_intelligence || null);
      setLayers(response.data.layers || null);
      setLoading(false);

    } catch (error) {
      console.error("Error:", error);
      alert("Error connecting to backend.");
      setLoading(false);
    }
  };

  let percentage = probability ? probability * 100 : 0;
  let basePercentage = baseProbability ? baseProbability * 100 : 0;

  // Determine threat level based on percentage (aligned with backend thresholds)
  let threatLevel = "";
  let color = "";
  let displayResult = "";

  if (percentage < 30) {
    threatLevel = "Low Risk";
    color = "#00ff88";
    displayResult = "Legitimate";
  } else if (percentage < 60) {
    threatLevel = "Medium Risk";
    color = "#ffae00";
    displayResult = "Suspicious";
  } else {
    threatLevel = "High Risk";
    color = "#ff0033";
    displayResult = "Phishing Detected";
  }

  // Clean up risk factors by removing emojis and formatting
  const cleanRiskFactor = (factor) => {
    // Remove emojis and extra formatting
    let cleaned = factor.replace(/[🚨⚠️📅🔍🎨🔓🌐📁➖📏🔀]/g, '');
    cleaned = cleaned.replace(/🚨|⚠️|📅|🔍|🎨|🔓|🌐|📁|➖|📏|🔀/g, '');
    cleaned = cleaned.trim();
    return cleaned;
  };

  // FIXED: Better Threat Breakdown using actual layer scores from backend
  const getThreatBreakdown = () => {
    // Use actual layer scores from backend if available
    if (layers) {
      return [
        { name: "ML Score", score: layers.ml_score || 0, color: "#8a2be2" },
        { name: "URL Structure", score: layers.url_structure || 0, color: "#ffae00" },
        { name: "Domain Reputation", score: layers.domain_reputation || 0, color: "#00ff88" },
        { name: "Content Analysis", score: layers.content_analysis || 0, color: "#ffae00" },
      ].filter(item => item.score > 0);
    }
    
    // Fallback: Calculate from risk factors
    let mlScore = basePercentage;
    let urlScore = 0;
    let domainScore = 0;
    let contentScore = 0;
    
    riskFactors.forEach(factor => {
      const f = factor.toLowerCase();
      if (f.includes("url") || f.includes("redirect") || f.includes("path")) {
        urlScore = Math.min(urlScore + 25, 100);
      }
      if (f.includes("domain") || f.includes("tld") || f.includes("new domain")) {
        domainScore = Math.min(domainScore + 35, 100);
      }
      if (f.includes("content") || f.includes("brand") || f.includes("impersonation")) {
        contentScore = Math.min(contentScore + 40, 100);
      }
    });
    
    // Also check threat intelligence
    if (threatIntel?.confirmed_phishing) {
      domainScore = 100;
    }
    
    return [
      { name: "ML Score", score: Math.min(mlScore, 100), color: "#8a2be2" },
      { name: "URL Structure", score: urlScore, color: "#ffae00" },
      { name: "Domain Reputation", score: domainScore, color: "#00ff88" },
      { name: "Content Analysis", score: contentScore, color: "#ffae00" },
    ].filter(item => item.score > 0);
  };

  // Improved timeline data using actual layer scores
  const getTimelineData = () => {
    if (layers) {
      return [
        { stage: "ML Analysis", value: Math.min(layers.ml_score || basePercentage, 100) },
        { stage: "URL Structure", value: Math.min(layers.url_structure || 0, 100) },
        { stage: "Domain Reputation", value: Math.min(layers.domain_reputation || 0, 100) },
        { stage: "Content Analysis", value: Math.min(layers.content_analysis || 0, 100) },
        { stage: "Final Score", value: percentage },
      ];
    }
    return [
      { stage: "URL Analysis", value: Math.min(basePercentage, 100) },
      { stage: "Domain Check", value: Math.min(percentage * 0.7, 100) },
      { stage: "Risk Aggregation", value: Math.min(percentage * 0.85, 100) },
      { stage: "Final Score", value: percentage },
    ];
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-panel">
        <h1 className="title">🛡️ FedShield - Threat Analysis Console</h1>

        <input
          type="text"
          placeholder="Enter website URL (e.g., https://example.com)..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="url-input"
        />

        <button onClick={handlePredict} className="scan-button">
          {loading ? "🔍 Analyzing..." : "🚀 Analyze Threat"}
        </button>

        {probability !== null && (
          <>
            <div
              className={`result-card ${
                percentage < 30
                  ? "result-low"
                  : percentage < 60
                  ? "result-medium"
                  : "result-critical"
              }`}
            >
              <div style={{ width: "150px", margin: "0 auto 20px auto" }}>
                <CircularProgressbar
                  value={percentage}
                  text={`${percentage.toFixed(1)}%`}
                  styles={buildStyles({
                    textColor: "white",
                    pathColor: color,
                    trailColor: "#222",
                  })}
                />
              </div>

              <div
                style={{
                  textAlign: "center",
                  fontSize: "20px",
                  marginBottom: "10px",
                  color: color,
                }}
              >
                {threatLevel}
              </div>

              <div style={{ textAlign: "center", marginBottom: "15px", fontSize: "24px", fontWeight: "bold" }}>
                {displayResult}
              </div>
            </div>

            <div className="soc-dashboard">
              <div className="soc-row">
                <div className="soc-card">
                  <h3>📊 Threat Breakdown by Layer</h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart 
                      data={getThreatBreakdown()} 
                      layout="vertical"
                      margin={{ left: 20, right: 20, top: 10, bottom: 10 }}
                    >
                      <XAxis type="number" stroke="#ccc" domain={[0, 100]} tickFormatter={(value) => `${value}%`} />
                      <YAxis type="category" dataKey="name" stroke="#ccc" width={120} />
                      <Tooltip formatter={(value) => `${value}%`} />
                      <Bar dataKey="score" fill="#8a2be2" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="soc-card">
                  <h3>📈 Risk Analysis Timeline</h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <LineChart data={getTimelineData()}>
                      <CartesianGrid stroke="#222" />
                      <XAxis dataKey="stage" stroke="#ccc" />
                      <YAxis stroke="#ccc" domain={[0, 100]} tickFormatter={(value) => `${value}%`} />
                      <Tooltip formatter={(value) => `${value}%`} />
                      <Line
                        type="monotone"
                        dataKey="value"
                        stroke="#8a2be2"
                        strokeWidth={3}
                        dot={{ r: 4, fill: "#8a2be2" }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="soc-row">
                <div className="soc-card">
                  <h3>⚠️ Triggered Risk Signals</h3>
                  <ul style={{ maxHeight: "250px", overflowY: "auto" }}>
                    {threatIntel?.confirmed_phishing && (
                      <li style={{ color: "#ff0033", marginBottom: "8px", fontWeight: "bold" }}>
                        🚨 CONFIRMED PHISHING - {threatIntel.source}
                      </li>
                    )}
                    {riskFactors.length > 0 && riskFactors.slice(1).map((factor, index) => (
                      <li key={`risk-${index}`} style={{ color: "#ffae00", marginBottom: "8px" }}>
                        ⚠️ {cleanRiskFactor(factor)}
                      </li>
                    ))}
                    {reasons.length > 0 && reasons.map((reason, index) => (
                      <li key={`reason-${index}`} style={{ marginBottom: "5px", color: "#888" }}>
                        📌 {reason}
                      </li>
                    ))}
                    {riskFactors.length === 0 && reasons.length === 0 && !threatIntel?.confirmed_phishing && (
                      <li>✅ No suspicious signals detected</li>
                    )}
                  </ul>
                </div>

                <div className="soc-card">
                  <h3>📋 Scan Metadata</h3>
                  <p><strong>URL:</strong> {url}</p>
                  <p><strong>ML Score:</strong> {basePercentage.toFixed(1)}%</p>
                  <p><strong>FedShield Score:</strong> <span style={{ color: color, fontWeight: "bold" }}>{percentage.toFixed(2)}%</span></p>
                  <p><strong>Improvement:</strong> <span style={{ color: percentage > basePercentage ? "#00ff88" : "#ffae00" }}>
                    {(percentage - basePercentage).toFixed(1)}%
                  </span></p>
                  <p><strong>Threat Level:</strong> <span style={{ color: color }}>{threatLevel}</span></p>
                  <hr style={{ borderColor: "#333", margin: "10px 0" }} />
                  <p><strong>Server IP:</strong> {ipInfo.ip || "Unknown"}</p>
                  <p><strong>Location:</strong> {ipInfo.country || "Unknown"}</p>
                  <p><strong>ISP:</strong> {ipInfo.isp || "Unknown"}</p>
                  <p><strong>ASN:</strong> {ipInfo.asn || "Unknown"}</p>
                  <p><strong>URL Reachable:</strong> {urlReachable ? "✅ Yes" : "❌ No"}</p>
                </div>
              </div>

              <div className="soc-card" style={{ marginBottom: "20px" }}>
                <h3>🌐 Domain Intelligence</h3>
                {domainInfo ? (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                    <div>
                      <p><strong>Domain:</strong> {domainInfo.domain || "Unknown"}</p>
                      <p><strong>Domain Age:</strong> {domainInfo.domain_age_days ? formatAge(domainInfo.domain_age_days) : "Unknown"}</p>
                      <p><strong>HTTPS:</strong> {domainInfo.has_https === 1 ? "✅ Yes" : "❌ No"}</p>
                      <p><strong>DNS Resolves:</strong> {domainInfo.dns_resolves === 1 ? "✅ Yes" : "❌ No"}</p>
                    </div>
                    <div>
                      <p><strong>Registrar:</strong> {domainInfo.registrar || "Unknown"}</p>
                      <p><strong>SSL Age:</strong> {domainInfo.ssl_age_days ? formatAge(domainInfo.ssl_age_days) : "Unknown"}</p>
                      {domainInfo.certificate_valid === false && (
                        <p><strong>⚠️ Certificate:</strong> Invalid</p>
                      )}
                      {domainInfo.is_platform_hosted && <p><strong>⚠️ Platform:</strong> {domainInfo.platform_name}</p>}
                      {domainInfo.suspicious_tld && <p><strong>⚠️ TLD:</strong> {domainInfo.suspicious_tld}</p>}
                    </div>
                  </div>
                ) : (
                  <p>No domain intelligence available</p>
                )}
              </div>

              {/* Layer Scores Card */}
              {layers && (
                <div className="soc-card" style={{ backgroundColor: "#1a1a2e", marginBottom: "20px" }}>
                  <h3>🔬 Detection Layer Scores</h3>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "15px", textAlign: "center" }}>
                    <div>
                      <p style={{ fontSize: "12px", color: "#888" }}>ML Score</p>
                      <p style={{ fontSize: "20px", fontWeight: "bold", color: "#8a2be2" }}>{layers.ml_score || 0}%</p>
                    </div>
                    <div>
                      <p style={{ fontSize: "12px", color: "#888" }}>URL Structure</p>
                      <p style={{ fontSize: "20px", fontWeight: "bold", color: "#ffae00" }}>{layers.url_structure || 0}%</p>
                    </div>
                    <div>
                      <p style={{ fontSize: "12px", color: "#888" }}>Domain Reputation</p>
                      <p style={{ fontSize: "20px", fontWeight: "bold", color: "#00ff88" }}>{layers.domain_reputation || 0}%</p>
                    </div>
                    <div>
                      <p style={{ fontSize: "12px", color: "#888" }}>Content Analysis</p>
                      <p style={{ fontSize: "20px", fontWeight: "bold", color: "#ffae00" }}>{layers.content_analysis || 0}%</p>
                    </div>
                  </div>
                </div>
              )}

              {/* FedShield Intelligence Note */}
              <div className="soc-card" style={{ backgroundColor: "#1a1a2e", borderLeft: "4px solid #8a2be2" }}>
                <h3>🧠 FedShield Intelligence</h3>
                <p style={{ fontSize: "14px", color: "#aaa" }}>
                  FedShield combines 5 detection layers: Threat Intelligence, Domain Reputation, URL Structure, Content Analysis, and ML Classification.
                  {basePercentage < 50 && percentage > 50 && (
                    <span style={{ color: "#00ff88", display: "block", marginTop: "10px" }}>
                      ✅ FedShield detected threats that pure ML missed!
                    </span>
                  )}
                  {percentage > 60 && (
                    <span style={{ color: "#ffae00", display: "block", marginTop: "10px" }}>
                      ⚠️ Multiple risk signals detected - Proceed with caution!
                    </span>
                  )}
                  {percentage < 30 && (
                    <span style={{ color: "#00ff88", display: "block", marginTop: "10px" }}>
                      ✅ No significant threats detected - URL appears legitimate.
                    </span>
                  )}
                </p>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default Dashboard;