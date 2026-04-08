import { createBrowserRouter } from "react-router";
import { Layout } from "./components/Layout";
import { Dashboard } from "./components/Dashboard";
import { EncryptView } from "./components/EncryptView";
import { VerifyDecryptView } from "./components/VerifyDecryptView";
import { KeyStoreView } from "./components/KeyStoreView";
import { SettingsView } from "./components/SettingsView";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: Dashboard },
      { path: "encrypt", Component: EncryptView },
      { path: "verify", Component: VerifyDecryptView },
      { path: "keystore", Component: KeyStoreView },
      { path: "settings", Component: SettingsView },
    ],
  },
]);
