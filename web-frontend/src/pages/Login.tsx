import React from "react";
import { Card, Button, OverlayTrigger, Popover } from "react-bootstrap";
import { ApiKey, Email } from "@innexgo/frontend-auth-api";
import LoginForm from '../components/LoginForm';
import { Branding } from '@innexgo/common-react-components';
import SidebarLayout from '../components/SidebarLayout';
import SendVerificationChallengeForm from "../components/SendVerificationChallengeForm";
import { InfoCircle } from 'react-bootstrap-icons';

type LoginProps = {
  branding: Branding,
}

function Login(props: LoginProps) {
  const { branding } = props;

  // the api key
  const [apiKey, setApiKey] = React.useState<ApiKey | null>(null);


  // the email we sent to
  const [sentEmail, setSentEmail] = React.useState<string | null>(null);
  const [sentParentEmail, setSentParentEmail] = React.useState<string | null>(null);


  const isAuthenticated = apiKey !== null &&
    apiKey.creationTime + apiKey.duration > Date.now() &&
    apiKey.apiKeyKind === "VALID";

  const searchParams = new URLSearchParams(window.location.search);
  const srcHref = searchParams.get("src");
  if (srcHref === null) {
    return <SidebarLayout branding={branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <Card.Title>Invalid Source</Card.Title>
            <Card.Text className="text-danger">The origin URL is invalid.</Card.Text>
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout>
  }

  if (isAuthenticated) {
    const destHref= new URL(srcHref);
    const newParams = new URLSearchParams({
      src: srcHref,
      apiKey: JSON.stringify(apiKey),
    });
    // target will use these internally
    destHref.search = newParams.toString();
    // now go
    window.location.replace(destHref);
  }

  const srcUrl = new URL(srcHref);

  const notLoggedIn = apiKey === null ||
    apiKey.creationTime + apiKey.duration <= Date.now() ||
    apiKey.apiKeyKind === "CANCEL";

  if (notLoggedIn) {
    return <SidebarLayout branding={branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <div className="d-flex justify-content-between">
              <Card.Title><h2>Login</h2> to {srcUrl.host}</Card.Title>

              <OverlayTrigger
                trigger="click"
                placement="auto"
                overlay={
                  <Popover id="information-tooltip">
                    <Popover.Header as="h3">Help</Popover.Header>
                    <Popover.Body>
                      <ul>
                        <li>
                          The page you are trying to access requires authentication.
                        </li>
                        <li>
                          You will be redirected to <u>{srcUrl.href}</u> after signing in.
                        </li>
                      </ul>
                    </Popover.Body>
                  </Popover>
                }
              >
                <button type="button" className="btn btn-sm">
                  <InfoCircle />
                </button>
              </OverlayTrigger>
            </div>
            <LoginForm branding={branding} onSuccess={setApiKey} srcOrigin={srcUrl.origin} />
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout>
  }

  if (sentEmail !== null) {
    return <SidebarLayout branding={branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <Card.Title>Verfication Email Sent!</Card.Title>
            <Card.Text>
              We successfully sent an email to {sentEmail}.
              You should use the link provided in the email to finish setting up your account.
              If you don't see our email, reload this page and try again.
            </Card.Text>
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout>
  }

  if (sentParentEmail !== null) {
    return <SidebarLayout branding={branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <Card.Title>Parent Verfication Email Sent!</Card.Title>
            <Card.Text>
              We successfully sent an email to {sentParentEmail}.
            </Card.Text>
            <Card.Text>
              If your parents don't see our email, reload this page and try again.
              Once your parent approves your account, you should be able to log in normally.
            </Card.Text>
            <Button onClick={() => setApiKey(null)}>Log In</Button>
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout>
  }


  if (apiKey.apiKeyKind === "NO_EMAIL") {
    return <SidebarLayout branding={branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <Card.Title>Verify Your Email</Card.Title>
            <SendVerificationChallengeForm
              toParent={false}
              initialEmailAddress=""
              setVerificationChallenge={x => setSentEmail(x.email)}
              apiKey={apiKey}
            />
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout>
  } else if (apiKey.apiKeyKind === "NO_PARENT") {
    return <SidebarLayout branding={branding}>
      <div className="h-100 w-100 d-flex">
        <Card className="mx-auto my-auto col-md-6">
          <Card.Body>
            <Card.Title>Verify Parent Email</Card.Title>
            <Card.Text>
              Because you indicated you are under 13, we need parent permission to finish setting up your account.
            </Card.Text>
            <SendVerificationChallengeForm
              toParent={true}
              initialEmailAddress=""
              setVerificationChallenge={x => setSentParentEmail(x.email)}
              apiKey={apiKey}
            />
          </Card.Body>
        </Card>
      </div>
    </SidebarLayout >
  } else {
    return <div />
  }
}

export default Login;
