import React, { useState } from "react";
import axios from "axios";
import "./App.css";

function App() {
  const [features, setFeatures] = useState("");
  const [result, setResult] = useState(null);
  const [probability, setProbability] = useState(null);
  const [loading, setLoading] = useState(false);

  const handlePredict = async () => {
    try {
      const featureArray = features.split(",").map(Number);

      if (featureArray.length !== 30) {
        alert("Please enter exactly 30 comma-separated values.");
        return;
      }

      setLoading(true);

      const response = await axios.post("http://127.0.0.1:5000/predict", {
        features: featureArray,
      });

      setResult(response.data.prediction);
      setProbability(response.data.probability);
      setLoading(false);
    } catch (error) {
      alert("Error connecting to backend.");
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>🔐 FederShield Phishing Detection</h1>

      <textarea
        rows="4"
        placeholder="Enter 30 comma-separated feature values..."
        value={features}
        onChange={(e) => setFeatures(e.target.value)}
      />

      <button onClick={handlePredict}>
        {loading ? "Analyzing..." : "Analyze URL"}
      </button>

      {result && (
        <div className={`result ${result}`}>
          <h2>Prediction: {result}</h2>
          <p>Confidence: {(probability * 100).toFixed(2)}%</p>
        </div>
      )}
    </div>
  );
}

export default App;
