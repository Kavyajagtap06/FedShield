import React from "react";
import { useNavigate } from "react-router-dom";
import "./landing.css";

function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="landing-container">
      <div className="landing-content">
        <h1 className="landing-title">FedShield</h1>
        <p className="landing-subtitle">
          AI-Powered Phishing Detection Platform
        </p>

        <button
          className="enter-button"
          onClick={() => navigate("/dashboard")}
        >
          Enter Command Center →
        </button>
      </div>
    </div>
  );
}

export default LandingPage;