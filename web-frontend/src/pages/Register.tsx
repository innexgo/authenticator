import React from 'react';
import { Card } from 'react-bootstrap'

import RegisterForm from '../components/RegisterForm';
import { Branding } from '@innexgo/common-react-components';
import { ApiKey, ApiKeyNewCancelProps } from '@innexgo/frontend-auth-api';

import { useNavigate } from 'react-router-dom';

import SidebarLayout from '../components/SidebarLayout';

// this function returns true if your account is incomplete
// if you're fully logged in, you can still view the register
// after you fill out the register though, you'll be automatically logged out
const createdInitialAccount = (apiKey: ApiKey | null) =>
  apiKey !== null &&
  apiKey.creationTime + apiKey.duration > Date.now()
  && (apiKey.apiKeyKind === "NO_EMAIL" || apiKey.apiKeyKind === "NO_PARENT");


type RegisterProps = {
  branding: Branding,
  apiKey: ApiKey | null,
  setApiKey: (a: ApiKey | null) => void
}

function Register(props: RegisterProps) {
  const navigate = useNavigate();
  return (
    <SidebarLayout branding={props.branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <>
              <Card.Title>Register</Card.Title>
              {createdInitialAccount(props.apiKey)
                // if authenticated go to home
                ? navigate(props.branding.dashboardUrl)
                // if not authenticated yet, then display this
                : <RegisterForm
                  onSuccess={apiKey => props.setApiKey(apiKey)}
                  tosUrl={props.branding.tosUrl}
                />
              }
            </>
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout>
  )
}

export default Register;
