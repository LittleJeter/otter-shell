import React from "react";
import { createRoot } from "react-dom/client";
import OtterShell from "./OtterShell.jsx";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <OtterShell />
  </React.StrictMode>
);
