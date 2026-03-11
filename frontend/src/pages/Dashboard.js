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
  const [result, setResult] = useState("");
  const [probability, setProbability] = useState(null);
  const [reasons, setReasons] = useState([]);
  const [loading, setLoading] = useState(false);
  const [features, setFeatures] = useState([]);
  const [domainInfo, setDomainInfo] = useState(null);
  const [ipInfo, setIpInfo] = useState({});

  // 👇 ADD IT HERE (after state, before return)
  const formatAge = (days) => {
    if (!days) return "Unknown";

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

      setResult(response.data.prediction);
      setProbability(response.data.probability);
      setReasons(response.data.reasons || []);
      setFeatures(response.data.features || []);
      setLoading(false);
      setDomainInfo(response.data.dynamic_signals || null);
      setIpInfo(response.data.ip_info || {});

    } catch (error) {
      alert("Error connecting to backend.");
      setLoading(false);
    }
  };

  // ================= RISK CALCULATION =================

  let percentage = probability ? probability * 100 : 0;

  let threatLevel = "";
  let color = "";

  if (percentage < 30) {
    threatLevel = "Low Risk";
    color = "#00ff88";
  } else if (percentage < 70) {
    threatLevel = "Medium Risk";
    color = "#ffae00";
  } else {
    threatLevel = "Critical Threat";
    color = "#ff0033";
  }

  // ================= SOC CATEGORY GROUPING =================

  const categoryGroups = {
    "URL Structure": [0, 1, 2, 3, 4],
    "Domain Risk": [5, 6, 7, 8],
    "HTML/JS Risk": [9, 10, 11, 12, 13],
    "SSL & Security": [14, 15, 16],
    "External Resources": [17, 18, 19, 20],
  };

  const threatBreakdown = Object.entries(categoryGroups).map(
    ([category, indexes]) => {
      let score = 0;

      indexes.forEach((i) => {
        if (features[i] === 1) score += 1;
      });

      return {
        name: category,
        score: Math.round((score / indexes.length) * 100),
      };
    }
  );

  // ================= TIMELINE DATA =================

  const timelineData = [
    { stage: "Initial Scan", value: 10 },
    { stage: "Structure Analysis", value: 35 },
    { stage: "Content Inspection", value: 60 },
    { stage: "Final Score", value: percentage },
  ];

  return (
    <div className="dashboard-container">
      <div className="dashboard-panel">
        <h1 className="title">Threat Analysis Console</h1>

        <input
          type="text"
          placeholder="Enter website URL..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="url-input"
        />

        <button onClick={handlePredict} className="scan-button">
          {loading ? "Analyzing..." : "Analyze Threat"}
        </button>

        {result && (
          <>
            {/* ================= RISK METER ================= */}
            <div
              className={`result-card ${
              percentage < 30
              ? "result-low"
              : percentage < 70
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

              <div style={{ textAlign: "center", marginBottom: "15px" }}>
                {result}
              </div>
            </div>

            {/* ================= SOC DASHBOARD ================= */}

            <div className="soc-dashboard">

              {/* Row 1 */}
              <div className="soc-row">

                <div className="soc-card">
                  <h3>Threat Breakdown</h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={threatBreakdown}>
                      <XAxis dataKey="name" stroke="#ccc" />
                      <YAxis stroke="#ccc" />
                      <Tooltip />
                      <Bar dataKey="score" fill="#8a2be2" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="soc-card">
                  <h3>Risk Analysis Timeline</h3>
                  <ResponsiveContainer width="100%" height={250}>
                    <LineChart data={timelineData}>
                      <CartesianGrid stroke="#222" />
                      <XAxis dataKey="stage" stroke="#ccc" />
                      <YAxis stroke="#ccc" />
                      <Tooltip />
                      <Line
                        type="monotone"
                        dataKey="value"
                        stroke="#8a2be2"
                        strokeWidth={3}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>

              </div>

              {/* Row 2 */}
              <div className="soc-row">

                <div className="soc-card">
                  <h3>Triggered Signals</h3>
                  <ul>
                    {reasons.map((reason, index) => (
                      <li key={index}>{reason}</li>
                    ))}
                  </ul>
                </div>

                <div className="soc-card">
                  <h3>Scan Metadata</h3>

                  <p><strong>URL:</strong> {url}</p>

                  <p><strong>Protocol:</strong>
                  {url.startsWith("https") ? " HTTPS" : " HTTP"}
                  </p>

                  <p><strong>Server IP:</strong> {ipInfo.ip || "Unknown"}</p>

                  <p><strong>Location:</strong> {ipInfo.country || "Unknown"}</p>

                  <p><strong>ISP:</strong> {ipInfo.isp || "Unknown"}</p>

                  <p><strong>ASN:</strong> {ipInfo.asn || "Unknown"}</p>

                  <p><strong>Risk Score:</strong> {percentage.toFixed(2)}%</p>

                  <p><strong>Threat Level:</strong> {threatLevel}</p>
                </div>

              </div>

              <div className="soc-card">
                <h3>Domain Intelligence</h3>

                {domainInfo && (
                  <>
                    <p>
                      <strong>Domain Age:</strong>{" "}
                      {domainInfo.domain_age_days
                        ? formatAge(domainInfo.domain_age_days)
                        : "Unknown"}
                    </p>

                    <p>
                      <strong>Registrar:</strong>{" "}
                      {domainInfo.registrar || "Unknown"}
                    </p>

                    <p>
                      <strong>SSL Certificate Age:</strong>{" "}
                      {domainInfo.ssl_age_days
                        ? formatAge(domainInfo.ssl_age_days)
                        : "Unknown"}
                    </p>

                    <p>
                      <strong>Name Servers:</strong>
                    </p>

                    {domainInfo.name_servers && domainInfo.name_servers.length > 0 ? (
                      <ul>
                        {domainInfo.name_servers.map((ns, index) => (
                          <li key={index}>{ns.replace(".", "")}</li>
                        ))}
                      </ul>
                    ) : (
                      <p>Unknown</p>
                    )}
                  </>
                )}
              </div>

            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default Dashboard;