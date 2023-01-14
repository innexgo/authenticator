
import React from 'react';
import { Card } from 'react-bootstrap'

import { Branding } from '@innexgo/common-react-components';
import { ApiKey, ApiKeyNewCancelProps } from '@innexgo/frontend-auth-api';

import { useNavigate } from 'react-router-dom';

import SidebarLayout from '../components/SidebarLayout';

type HomeProps = {
  branding: Branding,
  apiKey: ApiKey | null,
  setApiKey: (a: ApiKey | null) => void
}

function Home(props: HomeProps) {
  const navigate = useNavigate();
  return (
    <SidebarLayout branding={props.branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <Card.Title>Authenticator</Card.Title>
            <Card.Text>This application manages login credentials.</Card.Text>
            <ul>
            </ul>
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout>
  )
}

export default Home;
