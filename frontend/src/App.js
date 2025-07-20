import React from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ScanDashboard from "./components/ScanDashboard";

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<ScanDashboard />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;