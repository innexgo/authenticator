import React from "react";
import { Card, Button } from "react-bootstrap";
import { ApiKey, Email } from "@innexgo/frontend-auth-api";
import PartiallyAuthenticatedComponentProps from '../components/PartiallyAuthenticatedComponentProps';
import LoginForm from '../components/LoginForm';
import { Branding } from '@innexgo/common-react-components';
import SidebarLayout from '../components/SidebarLayout';
import SendVerificationChallengeForm from "../components/SendVerificationChallengeForm";

export interface PartiallyAuthenticatedComponentRendererProps {
  branding: Branding,
  component: React.ComponentType<PartiallyAuthenticatedComponentProps>,
  apiKey: ApiKey | null,
  setApiKey: (data: ApiKey | null) => void
}

function PartiallyAuthenticatedComponentRenderer(props: PartiallyAuthenticatedComponentRendererProps) {
  const { branding, component: PartiallyAuthenticatedComponent, apiKey, setApiKey } = props;
  const isAuthenticated = apiKey !== null &&
    apiKey.creationTime + apiKey.duration > Date.now()
    && apiKey.key != null;

  if (isAuthenticated) {
    return <PartiallyAuthenticatedComponent apiKey={apiKey} setApiKey={setApiKey} branding={branding} />
  } else {
    return <SidebarLayout branding={branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <Card.Title>Login</Card.Title>
            <LoginForm branding={branding} onSuccess={setApiKey} />
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout>
  }
}

export default PartiallyAuthenticatedComponentRenderer;
