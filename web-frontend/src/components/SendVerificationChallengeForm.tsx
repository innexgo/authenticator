import { Formik, FormikHelpers, FormikErrors } from 'formik'
import { Button, Form, } from 'react-bootstrap'
import { ApiKey, VerificationChallenge, verificationChallengeNew } from '@innexgo/frontend-auth-api';
import { isErr } from '@innexgo/frontend-common';

interface SendVerificationChallengeFormProps {
  toParent: boolean,
  initialEmailAddress: string,
  setVerificationChallenge: (vc: VerificationChallenge) => void
  apiKey: ApiKey,
}

function SendVerificationChallengeForm(props: SendVerificationChallengeFormProps) {
  type VerificationChallengeValues = {
    email: string,
  }

  const onSubmit = async (values: VerificationChallengeValues, { setStatus, setErrors }: FormikHelpers<VerificationChallengeValues >) => {
    // Validate input
    let errors: FormikErrors<VerificationChallengeValues> = {};
    let hasError = false;

    if (!values.email.includes('@')) {
      errors.email = "Invalid email address";
      hasError = true;
    }
    setErrors(errors);
    if (hasError) {
      return;
    }

    const passwordChangeResult = await verificationChallengeNew({
      email: values.email,
      toParent: props.toParent,
      apiKey: props.apiKey.key,
    });
    if (isErr(passwordChangeResult)) {
      switch (passwordChangeResult.Err) {
        case "API_KEY_UNAUTHORIZED": {
          setStatus("Please log back in and try again");
          break;
        }
        case "EMAIL_BOUNCED": {
          setErrors({ email: "This email address is invalid." });
          break;
        }
        case "EMAIL_COOLDOWN": {
          setStatus("Please wait 15 minutes before trying to send more emails.");
          break;
        }
        default: {
          setStatus("An unknown or network error has occured while trying to send the email.");
          break;
        }
      }
    } else {
      props.setVerificationChallenge(passwordChangeResult.Ok);
    }
  }
  return <>
    <Formik<VerificationChallengeValues>
      onSubmit={onSubmit}
      initialStatus=""
      initialValues={{
        email: props.initialEmailAddress,
      }}
    >
      {(props) => (
        <Form
          noValidate
          onSubmit={props.handleSubmit} >
          <Form.Group className="mb-3">
            <Form.Label >Email Address</Form.Label>
            <Form.Control
              name="email"
              type="email"
              placeholder="Email"
              value={props.values.email}
              onChange={props.handleChange}
              isInvalid={!!props.errors.email}
            />
            <Form.Control.Feedback type="invalid">{props.errors.email}</Form.Control.Feedback>
          </Form.Group>
          <Form.Group className="mb-3">
            <Button type="submit">Send Verification Email</Button>
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Text className="text-danger">{props.status}</Form.Text>
          </Form.Group>
        </Form>
      )}
    </Formik>
  </>
}

export default SendVerificationChallengeForm;
