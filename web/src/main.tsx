import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles/global.css";
import { connect } from "./api/store";
import { App } from "./App";

connect();
createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
