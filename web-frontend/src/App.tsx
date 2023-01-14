import React from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';

import { ApiKey } from '@innexgo/frontend-auth-api';

// public pages
import HomePage from './pages/HomePage';
import Error404 from './pages/Error404';

// login
import LoginPage from './pages/Login';

// register and auth pages
import RegisterPage from './pages/Register';
import EmailConfirmPage from './pages/EmailConfirm';
import ParentPermissionConfirmPage from './pages/ParentPermissionConfirm';
import ForgotPasswordPage from './pages/ForgotPassword';
import ResetPasswordPage from './pages/ResetPassword';

// other pages
import Account from './pages/Account';

import LightAdaptedIcon from "./img/atlas_icon_light.png";
import DarkAdaptedIcon from "./img/atlas_icon_dark.svg";

// Bootstrap CSS & JS
import './style/style.scss';
import 'bootstrap/dist/js/bootstrap';
import PartiallyAuthenticatedComponentRenderer from './components/PartiallyAuthenticatedComponentRenderer';

function getPreexistingApiKey() {
  const preexistingApiKeyString = localStorage.getItem("apiKey");
  if (preexistingApiKeyString == null) {
    return null;
  } else {
    try {
      // TODO validate here
      return JSON.parse(preexistingApiKeyString) as ApiKey;
    } catch (e) {
      // try to clean up a bad config
      localStorage.setItem("apiKey", JSON.stringify(null));
      return null;
    }
  }
}


function App() {
  const [apiKey, setApiKeyState] = React.useState(getPreexistingApiKey());
  const apiKeyGetSetter = {
    apiKey: apiKey,
    setApiKey: (data: ApiKey | null) => {
      localStorage.setItem("apiKey", JSON.stringify(data));
      setApiKeyState(data);
    }
  };

  const branding = {
    name: "Authenticator",
    tagline: "Account management service",
    homeUrl: "/",
    dashboardUrl: "/account",
    tosUrl: "/terms_of_service",
    darkAdaptedIcon: DarkAdaptedIcon,
    lightAdaptedIcon: LightAdaptedIcon,
  }

  return <BrowserRouter>
    <Routes>

      {/* Home Page */}
      <Route path="/" element={<HomePage {...apiKeyGetSetter} branding={branding} />} />

      {/* Login Page (used by other applications) */}
      <Route path="/login" element={<LoginPage branding={branding} />} />

      {/* Necessary for the backend auth service */}
      <Route path="/register" element={<RegisterPage {...apiKeyGetSetter} branding={branding} />} />
      <Route path="/forgot_password" element={<ForgotPasswordPage branding={branding} />} />
      <Route path="/reset_password" element={<ResetPasswordPage branding={branding} />} />
      <Route path="/email_confirm" element={<EmailConfirmPage {...apiKeyGetSetter} branding={branding} />} />
      <Route path="/parent_permission_confirm" element={<ParentPermissionConfirmPage branding={branding} />} />

      {/* Requires you to be logged in */}
      {/* Using PartiallyAuthenticatedComponentRenderer */}
      <Route path="/account" element={<PartiallyAuthenticatedComponentRenderer branding={branding} {...apiKeyGetSetter} component={Account} />} />

      {/* Error page */}
      <Route path="*" element={<Error404 />} />
    </Routes >
  </BrowserRouter >
}

export default App;
